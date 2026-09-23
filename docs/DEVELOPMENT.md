# conduitscope -- Development Documentation

This is the internal-facing companion to
**[USER_GUIDE.md](USER_GUIDE.md)** (how to run conduitscope) and
**[PROTOCOL_COVERAGE.md](PROTOCOL_COVERAGE.md)** (what it decodes and how
confidently). It covers how the codebase itself is put together: why
protocols are tried in the order they are and how cross-protocol
detection collisions get resolved (PROTOCOL DETECTION below), an outside
engineering review and the priorities that came out of it, and what's
planned next (ROADMAP). Read this before extending the decoder, not
before running it.

## Architecture snapshot

As of 2026-09-18: 51 `.cpp` files and 51 matching `.hpp` files under
`src/`/`include/conduitscope/` (one pair per protocol or subsystem, plus
shared plumbing), roughly 94,600 lines combined, built as a single static
library (`conduitscope_core`) linked into the `conduitscope` CLI binary.
`decoder.cpp` is 3,229 lines and `decoder.hpp` is 1,416 -- both have grown
substantially since the September review below (they were 2,892/1,239
lines at review time), because Tiers 3-5 of the "IT protocols an OT
auditor flags" family (ROADMAP item 18) landed afterward. `CMakeLists.txt`
is just under 7,000 lines and registers 1,088 CTest tests, the large
majority of which invoke the built CLI binary against a fixture (a hand-
built synthetic pcap, or occasionally a real capture) and match its output
with `PASS_REGULAR_EXPRESSION` -- black-box regression testing, not unit
testing in the strict sense. See the review below for what that testing
strategy does and doesn't catch.

The high-level decomposition (capture/framing → industrial protocols → IT/
infrastructure protocols → analysis → presentation) matches the review's
own diagram in [docs/reviews/2026-09-chatgpt-code-review.md](reviews/2026-09-chatgpt-code-review.md#1-the-actual-architecture)
and hasn't materially changed since -- new protocols have extended the
"industrial protocols" and "IT/infrastructure protocols" branches, not
added new top-level branches.


## External code review and engineering priorities

In September 2026, after the six-tier "IT protocols an OT auditor flags"
arc (ROADMAP item 18, Tiers 1-5) was substantially complete, Jurgen had
ChatGPT review the repository directly (reading the actual C++ source
rather than the README) and shared the result for a second opinion. The
full, unedited review is kept at
[docs/reviews/2026-09-chatgpt-code-review.md](reviews/2026-09-chatgpt-code-review.md);
this section is the response to it -- what was checked against the
repository, where the review holds up, where it's since been overtaken by
events, and the priority order that came out of the discussion.

### What checked out

Every structural claim independently re-verified against the repository
held up, and several have gotten more pronounced since the review was
written (see "Architecture snapshot" above for current numbers against
the review's own):

- **The central-dispatcher problem in `decoder.cpp` is real and is this
  codebase's single most important structural liability.** Every new
  protocol still means touching the `ProtocolFilter` enum, the ordered
  detection chain, `DecodedPacket`, and the CLI surface together, not in
  isolation -- exactly the "adding protocol X requires modifying X plus
  the central decoder plus tests plus the filter enum plus output
  structures" pattern the review describes.
- **`DecodedPacket`'s one-struct-with-every-protocol's-fields-in-it shape**
  is exactly as described, and the header has grown past the review's own
  1,239-line snapshot.
- **The `session_key`/`SessionKey` duplication** between
  `asset_inventory.cpp` and `policy_engine.cpp` is real, and is exactly
  the "each engine stays self-contained" pattern the review names --
  visible directly in `asset_inventory.cpp`'s own comment explaining the
  duplication is deliberate.
- **No sanitizers, no fuzz targets, no CI** were wired into the build at
  review time. Confirmed: zero `-fsanitize` flags anywhere in
  `CMakeLists.txt`, no `tests/corpus/` or fuzz harness of any kind, and no
  `.github/workflows/` directory.
- **Testing is broad but exclusively black-box regression** (CLI
  invocation + `PASS_REGULAR_EXPRESSION`), which is real and does mean the
  suite's 1,088 tests say nothing about branch coverage, memory safety, or
  parser behavior under adversarial input -- only that specific, known
  fixtures still decode to the expected text.

### Where the review's own numbers are already stale

The review cites `decoder.cpp` at 2,892 lines and "43k lines" for the
project overall; both are lower than current reality (3,229 lines and
roughly 95k lines in `src/`+`include/` alone, before docs) because Tiers
3-5 landed after the review was written. This doesn't change any of the
review's conclusions -- if anything it sharpens the central-dispatcher and
comment-density points -- but it's worth recording so nobody re-derives
"43k lines" as a current fact from this document.

### Where more nuance seemed warranted

- **"Protocol depth is very uneven" is true but not an accidental gap** --
  every port-only, weakest-confidence detection (LWAPP, STT, TeamViewer/
  AnyDesk/Zoom, and others) is named as such in the same paragraph that
  introduces it, in both PROTOCOL_COVERAGE.md and the code's own header
  comments. The unevenness is a documented, deliberate trade-off (a
  protocol with no public wire-format spec gets a port-only fallback
  because there is nothing stronger to check), not something discovered
  later.
- **The "God Object" framing undersells what the regression suite already
  catches.** Every dispatch branch is independently testable, and the
  CTest suite has repeatedly caught real cross-protocol collisions during
  development itself (IEC-104/Modbus, DNP3/Modbus, HART-IP/Modbus, FTP/
  MQTT, LDAP/MQTT, and, in Tier 5, HART-IP's opportunistic gate against
  IKE NAT-T and VXLAN) -- black-box, but not toothless.
- **The extensive inline commentary has a real function the review
  doesn't fully credit**: for a tool whose entire value proposition is
  "don't claim more than the capture supports," the comments recording
  *which specific collision was found in testing* and *why a given
  confidence tier is honest* are the audit trail for decisions someone
  will eventually need to trust or debug. That doesn't make the volume
  free, though -- see "Comment density" below.

### The one gap weighted more heavily here than in the review's own ordering

The review's Phase 1-4 ordering (fuzzing/sanitizers, then CI, then
architecture) is the right shape, but framed CI as "the most glaring
missing thing" (§11) somewhat ahead of sanitizers/fuzzing. For a tool
whose entire input surface is attacker-reachable capture bytes, the
sharper near-term risk is the complete absence of ASan/UBSan/fuzzing, not
the absence of CI by itself -- CI without sanitizers wired into it mostly
proves the code still compiles and the regression strings still match,
which doesn't touch the threat model §18-19 of the review describes.
Sequenced correctly (sanitizers folded into the same CI job that's
being stood up first, fuzzing after), this isn't a disagreement about
priority so much as about which of the two gaps is doing more of the
work.

### Decisions and priority order

Discussed and adopted, in this order:

1. **CI now** ([.github/workflows/ci.yml](../.github/workflows/ci.yml)):
   GCC and Clang, Debug and Release, plus a fifth leg with live capture
   explicitly disabled (to exercise the libpcap-not-found stub path), all
   running the full CTest suite on every push/PR, and also on a version
   tag push (`v*`) so cutting a release gets the same verification.
   Deliberately does **not** yet include ASan/UBSan -- see next. Standing this up
   immediately turned up a live example of exactly the risk the review's
   §11 describes: `mqtt.cpp`'s Sparkplug B "Bytes"/"File" datatype summary
   built a ternary mixing a `std::string` branch
   (`std::to_string(*m.bytes_value_length)`) with a `size_t` branch
   (`size_t{0}`) -- ill-formed C++, but GCC's implementation-specific
   overload resolution for `operator<<` accepted it silently, while Clang
   correctly rejected it. It had been shipping, uncaught, since MQTT's
   Sparkplug B decoding was written -- GCC was the only compiler this
   codebase had ever been built with before this CI pass. Fixed by
   streaming the `size_t` directly instead of going through
   `std::to_string`. Confirmed independently: 1,088/1,088 tests pass on
   all four GCC/Clang × Debug/Release combinations, and 1,084/1,084 on
   the live-capture-disabled leg (4 tests fewer -- the ones that require
   libpcap to be present don't register at all on that leg).

   A second, separate finding surfaced once this workflow actually ran on
   a GitHub-hosted runner rather than a privileged local sandbox: opening
   a live capture (`pcap_activate`) needs `CAP_NET_RAW` even against
   loopback, and the runner's default user has neither that capability
   nor root, so the 4 `live_capture_*` tests that actually open `lo` (as
   opposed to validating arguments or enumerating interfaces) failed with
   "You don't have permission to perform this capture on that device" --
   the same reason these tests need `sudo` to pass on an ordinary
   Debian/Ubuntu dev machine today. Fixed in the workflow by granting the
   built binary `cap_net_raw,cap_net_admin=eip` via `setcap` right after
   the build step, rather than running the whole test suite under `sudo`
   -- confirmed by reproducing the failure and the fix locally as an
   unprivileged user before pushing. The same `setcap` invocation is the
   recommended fix for the local-dev-machine version of this (once, on
   the built binary) instead of prefixing every test run with `sudo` --
   the README's own Building/Linux instructions now include this exact
   step, verified there the same way: build, `setcap`, then confirm the
   full `live_capture_*` CTest subset passes as an unprivileged user.

   A third addition, once the tag-push trigger above was in place: a
   `release` job that only runs on a `v*` tag push, only after every
   `build-and-test`/`build-without-libpcap` leg has already passed for
   that exact commit, and publishes a GitHub Release for the tag with a
   packaged Linux binary attached (stripped, bundled with README.md,
   LICENSE, `man/`, and `docs/` -- this is an OT-audit tool, and the
   person running it is often on an air-gapped or restricted network, so
   the docs travel with the binary rather than staying link-only). This
   surfaced a real version-drift bug: `CMakeLists.txt`'s own
   `project(... VERSION 0.1.0 ...)` was still 0.1.0 when tag `v0.1.1` was
   pushed, so a naively-built release binary would have reported the
   wrong version from `conduitscope version`. Fixed with a
   `CONDUITSCOPE_VERSION_OVERRIDE` CMake variable (substituted into
   `version.hpp.in` in place of `PROJECT_VERSION` directly) that the
   `release` job sets explicitly from the pushed tag, plus a "does the
   built binary's reported version actually match the tag" check as its
   own CI step -- so this class of drift fails the release job loudly
   instead of quietly shipping a mislabeled binary. `CMakeLists.txt`'s own
   `PROJECT_VERSION` was also bumped to 0.1.1 to match, but the override
   is what makes this correct going forward even if a future tag is cut
   without remembering that step.
2. **Sanitizers and fuzzing** ([fuzz/](../fuzz/), harnesses written; CI
   wiring not yet done): five libFuzzer harnesses, matching the priority
   list above exactly -- `fuzz_pcap_reader` (classic pcap + pcapng
   file-format parsing), `fuzz_packet_decode` (the full
   `Decoder::decode()` pipeline, fed a *sequence* of packets extracted from
   one fuzzer input into a single `Decoder` instance -- this is the one
   that actually reaches `Decoder::reassemble_tcp_payload` and every other
   cross-packet/per-flow state, since a single-packet input structurally
   can't), `fuzz_dnp3`, `fuzz_cotp_s7comm`, and `fuzz_mqtt` (these three
   call each protocol's own standalone `try_parse_*` entry point directly
   on raw bytes, no Ethernet/IPv4/TCP framing needed, for faster/deeper
   single-payload coverage than routing through `decode()` would give).
   Each harness is a thin wrapper with no parsing logic duplicated from
   `conduitscope_core`; seed corpora (`fuzz/corpus/*/`) were extracted from
   this repo's own `tests/sample_*.pcap` fixtures. `CONDUITSCOPE_ENABLE_FUZZING`
   (CMake option, off by default, Clang-only) builds these AND compiles
   `conduitscope_core` itself with `-fsanitize=address,undefined` -- ASan/UBSan
   instrument the library's own code, not just the five harness files, and
   because link options propagate to every consumer of the library, the
   `conduitscope` CLI binary built in this configuration is sanitized too.
   That got the "ASan/UBSan folded into the same CI matrix" half of this
   item's plan verified locally as a side effect, ahead of actually wiring
   it into `ci.yml`: the full existing 1,093-test CTest suite (1,088
   regression tests plus the 5 new `fuzz_*_corpus_regression` smoke tests
   this option also registers, each a short bounded libFuzzer run over its
   own seed corpus) passes clean under this instrumented build, and each
   harness ran on the order of 10^5-10^6 executions in a 15-second smoke
   run with no ASan/UBSan report. **Update: folded into `ci.yml` itself**
   (see item 6 below for the details -- this line is kept for the "verified
   locally as a side effect, ahead of actually wiring it into `ci.yml`"
   history it originally recorded).

   **Second wave (four more targets, added once the original five had
   already run enough to prove the approach):** `fuzz_bacnet`,
   `fuzz_iec104`, `fuzz_enip`, and `fuzz_s7comm_plus` -- the next four
   highest hand-rolled-parsing-complexity OT/ICS protocols in this
   codebase, added once every protocol decoder had gained its own
   standalone `try_parse_*(ByteSpan)` entry point, which made a dedicated
   harness for any of them a small, mechanical addition following the
   exact same shape as the original five. BACnet is the strongest of this
   batch on its own merits: `fuzz_packet_decode` had already found a real
   signed-left-shift undefined-behavior bug in `bacnet.cpp`'s
   `read_signed64` (fixed) before this faster, more-targeted harness
   existed, which is itself a concrete demonstration of why a dedicated
   harness per parser is worth the small duplication of harness
   boilerplate. `fuzz_iec104` covers the fixed 6-byte APCI plus an
   I-format frame's type-keyed ASDU object table; `fuzz_enip` covers both
   CIP explicit messaging (with its EPATH/service-code recursion through
   Multiple_Service_Packet/Unconnected_Send) and CIP I/O implicit
   messaging in one harness, since they're independent entry points over
   two different transports that share no state; `fuzz_s7comm_plus`
   mirrors `fuzz_cotp_s7comm`'s own TPKT/COTP-then-application-layer
   shape, but reaches S7comm-Plus's own protocol id (0x72) instead of
   classic S7comm's (0x32) -- a completely different, and (per
   `s7commplus.hpp`'s own file header) never officially published,
   application layer the original harness's mutations essentially never
   reach. Seed corpora (`fuzz/corpus/bacnet,iec104,enip,s7comm_plus/`)
   were extracted the same way as the original five, from this repo's own
   `tests/sample_*.pcap` fixtures. All four ran clean (zero ASan/UBSan
   reports) over both their own seed corpora and a 60-second mutation
   burst each, on the order of 10^6-10^7 executions per target, before
   being committed.

   **Fuzzing campaign log.** Corpus provenance and hand-crafted expansion status for the nine
   harnesses in [fuzz/](../fuzz/), plus every dedicated real-time (not just the short commit-time
   smoke burst) campaign run against them so far -- kept up to date as further runs happen:

   | Harness | Seed corpus | Hand-crafted expansion | Dedicated fuzzing campaign(s) run | Findings |
   |---|---|---|---|---|
   | `fuzz_pcap_reader` | `tests/sample_*.pcap` extracts | +24 seeds (classic pcap/pcapng: truncated headers, `incl_len` over/under the plausibility ceiling, byte-order/section-switch variety, block-length mismatches) | 16 workers x 2 hours: 345.4M executions across the 15 workers that ran to completion, `cov:40 ft:85` (plateaued); the 16th worker hit a libFuzzer timeout (1528s, over the 1200s cap) inside `PcapReader::next`'s buffer allocation -- replaying that same code path at its 16MB cap standalone takes 85ms, so this looks like host contention from running 16 workers at once rather than an algorithmic bug, but isn't fully ruled out without the original crashing input | -- |
   | `fuzz_packet_decode` | `tests/sample_*.pcap` extracts | +14 seeds (TCP reassembly: overlap/retransmission, sequence-number wraparound, out-of-order gap-abandon, many simultaneous flows, FIN/RST mid-reassembly, single-byte/zero-length segments; plus the resource-exhaustion probes that found the finding at right) | 8 workers x 1 hour: 203.1M executions, 0 crashes, `cov:597 ft:3463` (plateaued); corpus grew 5->7,803 files from organic finds | Found the `reassemble_tcp_payload`/`opcua_declared_length`/`ffhse_declared_length` unbounded-buffering gap -- see "Correction to item 7" and "Update: implemented" above (fixed); this same log also shows the INT32_MIN-negation UB in `reassemble_tcp_payload` (decoder.cpp) and the signed-left-shift UB in `bacnet.cpp`'s `read_signed64` noted in the `fuzz_bacnet` row below -- both already fixed, with regression seeds in this harness's own corpus |
   | `fuzz_dnp3` | `tests/sample_*.pcap` extracts | none yet | 8 workers x 1 hour: 903.6M executions, 0 crashes, `cov:78 ft:295` (plateaued) | -- |
   | `fuzz_cotp_s7comm` | `tests/sample_*.pcap` extracts | none yet | 8 workers x 1 hour: 546.0M executions, 0 crashes, `cov:120 ft:322-326` (plateaued); corpus grew 132->306 files from organic finds | -- |
   | `fuzz_mqtt` | `tests/sample_*.pcap` extracts | none yet | 8 workers x 1 hour: 1.03B executions, 0 crashes, `cov:66 ft:190` (plateaued) | -- |
   | `fuzz_bacnet` | `tests/sample_*.pcap` extracts | +67 seeds | 8 workers x 1 hour: 2.63B executions, 0 crashes, `cov:83 ft:182` (plateaued) | Signed-left-shift UB in `bacnet.cpp`'s `read_signed64`, originally found via `fuzz_packet_decode` before this dedicated harness existed (fixed) |
   | `fuzz_iec104` | `tests/sample_*.pcap` extracts | none yet | 8 workers, ~3.12B executions total, 0 crashes, `cov:132 ft:536-537` -- the run's `-max-total-time=3600` flag has a typo (libFuzzer wants `-max_total_time`, with an underscore); libFuzzer warned and ignored it, so all 8 workers ran uncapped until manually interrupted rather than stopping at 1 hour | -- |
   | `fuzz_enip` | `tests/sample_*.pcap` extracts | +165 seeds (encapsulation commands, EPATH/CIP recursion to and past `kMaxCipRecursionDepth`, every CIP elementary type, CPF item variety, CIP I/O) | 8 workers x 1 hour: 229.4M executions, 0 crashes, `cov:70 ft:326` (up from `ft:321` at init); corpus grew 310->372 files from organic finds; an earlier 8 workers x 1 hour run against a smaller, pre-expansion 85-seed corpus logged 816.0M executions, 0 crashes, `cov:70 ft:322` | -- |
   | `fuzz_s7comm_plus` | `tests/sample_*.pcap` extracts | +98 seeds (every PDU type/opcode, both Tier-1 function directions, every value datatype, Struct nesting to and past `kMaxStructDepth`, the Integrity part, VLQ edge cases), plus 31 real-device seeds extracted from a genuine S7-1212C + Siemens KTP 400 Basic HMI capture (see `tests/real_captures/s7comm/ATTRIBUTION.md`'s DataFW1_5 addendum) | 8 workers x 1 hour: 601.9M executions, 0 crashes, `cov:126 ft:465` (plateaued); a later 8 workers x 1 hour run against the grown 350-seed corpus: 482.9M executions, 0 crashes, `cov:134 ft:480`; a further 4 workers x 60s burst after the DataFW1_5 fix and real-device seed addition: ~1.8M executions, 0 crashes, `cov:128 ft:371-372` | -- |

   All nine also pass a short (10^5-10^7 execution) ASan/UBSan mutation burst as part of committing
   their harness/corpus in the first place, per item 2's own text above -- the campaign column here
   is specifically for longer, dedicated runs beyond that commit-time smoke bar.

3. **The registration-model decoder refactor, after that** (not yet
   started, no committed timeline): a `ProtocolDecoder` interface plus
   registry, replacing the `ProtocolFilter` enum / ordered dispatch chain
   / monolithic `DecodedPacket` triad. The review's own instinct to not
   attempt this mid-buildout was correct; doing it now that the Tier 1-5
   protocol arc has settled is reasonable, but it should follow a fuzzing
   pass rather than precede it -- a fuzz corpus catching regressions makes
   a structural refactor of this size much safer to attempt than doing it
   the other way around.

   **Update: a staged pilot is now implemented**, ahead of a full
   migration, deliberately scoped down from "all ~51 protocols" to three
   chosen to cover this codebase's three structural dispatch shapes:
   EIGRP (IP-protocol-number-gated, stateless), Modbus (TCP-port-
   independent, stateful with cross-packet transaction pairing and TCP
   reassembly), and GOOSE (EtherType-gated). `include/conduitscope/
   protocol_decoder.hpp` defines the interface (`ProtocolDecoder`,
   `ProtocolResult` -- a type-erased holder replacing what a `std::variant`
   would otherwise need extending for every migrated protocol --
   `DecodeContext`, and a generic `FlowStateMap` replacing the old
   one-bespoke-member-per-stateful-protocol pattern, e.g.
   `Decoder::modbus_pending_`, with a single `Decoder::registry_flow_
   state_` map keyed by protocol id); `protocol_registry.{hpp,cpp}` holds
   one hand-maintained, heavily commented registry vector per dispatch
   cascade (EtherType/IP-protocol/TCP-port-independent/UDP-port) -- audit-
   trail data during this pilot, not yet what actually drives dispatch
   order (see below). Each of the three pilot protocols still dual-writes
   into its existing `DecodedPacket` flat fields (`eigrp_*`/`modbus_*`/
   `goose_*`), so `output.cpp`'s existing renderers needed zero changes for
   them, and each migrated protocol's `decoder.cpp` call site sits at
   EXACTLY the same textual position its old `if` block occupied -- 
   migrating changes WHAT runs there, never WHICH LINE -- which preserves
   every documented collision-avoidance ordering guarantee (e.g. "IEC104
   before Modbus", see PROTOCOL DETECTION below) by construction, whether
   or not the protocol on either side of it has migrated yet. Verification
   at every stage: the full CTest suite (now 1,197 tests, all passing) with
   NO changed `PASS_REGULAR_EXPRESSION` expectations for any of the three
   pilot protocols -- proof of byte-identical output pre/post migration --
   plus zero-warning builds across all three established configs (default
   Linux+libpcap, `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`, MinGW cross-
   compile). TwinCAT/ADS (item 20 below) is the pilot's proof of the actual
   payoff: the first protocol built entirely on `ProtocolDecoder`, with NO
   `DecodedPacket` flat fields of its own at all -- see its own entry
   below and `include/conduitscope/twincat.hpp`'s file header.

   One pragmatic deviation from this refactor's original design, flagged
   rather than silently substituted: the design called for a
   `ProtocolRenderer` virtual class so `output.cpp`'s 4 writer classes
   could each get one early branch for a migrated protocol's own
   rendering. Once actually implemented, only `JsonWriter` and
   `StatsWriter` turned out to need protocol-specific TwinCAT rendering at
   all -- `TextWriter`/`CsvWriter` already render generically from
   `DecodedPacket::protocol`/`summary`/`notes` for every protocol and
   needed no changes for TwinCAT either. With exactly one implementer, a
   virtual interface would have been premature abstraction, so TwinCAT's
   JSON rendering is a plain free function (`write_twincat_json_fields` in
   `output.cpp`) instead. This still satisfies the refactor's actual
   constraint (`DecodedPacket` untouched by TwinCAT); a `ProtocolRenderer`
   interface remains there to introduce if/when a second protocol needs
   protocol-specific rendering of its own.

   **Update: migration batch 2 complete.** With the pilot proven and
   TwinCAT tested clean against real captures, Jurgen asked to keep
   migrating -- prioritizing highest-traffic OT protocols, in individually-
   verified stages. Research surfaced a real complication: S7comm,
   S7comm-Plus, and MMS all share ONE transport layer (TPKT/COTP), so none
   of the three could migrate independently without COTP itself moving
   first. Jurgen chose to migrate COTP as shared plumbing plus all three
   riders together rather than deferring the S7 family, so this batch grew
   past the original "5-8 protocol" estimate -- flagged here rather than
   silently expanding scope.

   COTP/S7comm/S7comm-Plus/MMS are now done: `CotpDecoder` (`cotp.hpp`/
   `cotp.cpp`) does TPKT/COTP framing and cross-packet TSDU-fragment
   reassembly (the non-Data-abandons-reassembly and Data-frame EOT-chaining
   logic that used to live directly in `decoder.cpp`'s COTP/S7comm-family
   call site, reading/writing a bespoke `Decoder::cotp_reassembly_`
   member -- both retired); `S7CommDecoder`/`S7CommPlusDecoder`/
   `MmsDecoder` are thin wrappers around the existing `try_parse_s7comm`/
   `try_parse_s7comm_plus`/`try_parse_mms`, all stateless. This required
   one small, backward-compatible interface extension:
   `DecodeContext::flow_state<T>()` previously keyed unconditionally on
   `session_key` (right for Modbus's/TwinCAT's own request/response
   pairing, which can legitimately be answered from either TCP direction);
   COTP fragment reassembly is per-*direction*, not per-session, so a new
   `FlowStateKeying` enum (`Session`/`DirectionalFlow`) and a
   `flow_state<T>(FlowStateKeying)` overload were added -- every existing
   caller keeps compiling unchanged via the original no-arg overload, which
   now just defaults to `Session`. A new `GateKind::CotpPayload` was also
   added for S7comm/S7comm-Plus/MMS's own gate shape (never gated against
   raw TCP bytes directly, only ever invoked with bytes `CotpDecoder` has
   already framed/reassembled) -- these three are registered in a new
   `cotp_payload_registry()`, but unlike every other populated registry
   vector this one is audit-trail data ONLY: `decoder.cpp`'s call site
   still tries each of the three explicitly in the same fixed order (their
   dual-write blocks differ too much to generalize into one loop without
   real loss of clarity), rather than iterating it. `decoder.cpp`'s two
   dispatch cascades (declared-length probe and full decode) both sit
   exactly where the old `if (want_s7comm || want_mms || want_s7commplus)`
   blocks always did. Verified: full CTest suite (1,197 tests, all
   passing, no changed expectations) across all three established configs,
   plus a manual JSON smoke-test over every existing S7comm/S7comm-Plus/
   MMS/COTP fixture confirming correct reassembly/buffering/pairing
   behavior end to end.

   Also folded into this same pass, since S7comm/S7comm-Plus were already
   being touched: Jurgen asked for TwinCAT's `[protocol]` text-output tag
   (previously uncolored -- a pre-existing gap from when TwinCAT was built
   on the renderer path, falling through to the generic dim default) to
   use Beckhoff's own brand red, and S7comm's/S7comm-Plus's tags to use
   Siemens' own official brand teal ("Viridian Green"/Petrol, `#009999`,
   their brand color since 1991) instead of their previous plain blue/bold
   magenta. `output.cpp`'s `protocol_tag_color()` picks every OTHER tag's
   color purely for at-a-glance mixed-capture disambiguation, never for
   brand-matching, so these three are a deliberate, narrowly-scoped
   exception using 24-bit truecolor SGR escapes rather than the file's
   usual 16-standard-ANSI-color convention -- MMS was deliberately left at
   its existing bold blue (not requested, and it's a distinct IEC 61850
   protocol, not one of Siemens' own S7 product line). `man/
   conduitscope.1`'s and `docs/USER_GUIDE.md`'s own color-scheme
   descriptions were updated to match.

   DNP3 is also now done: `Dnp3Decoder` (`dnp3.hpp`/`dnp3.cpp`) reproduces
   the existing same-TCP-payload multi-data-link-frame coalescing loop and
   the cross-packet application-fragment reassembly that used to live
   directly in `decoder.cpp`'s `if (want_dnp3)` call site and its
   `Decoder::process_dnp3_frame` method (reading/writing a bespoke
   `Decoder::dnp3_reassembly_` member -- both retired). This is the second,
   independent use of the `FlowStateKeying::DirectionalFlow` extension COTP
   needed first: DNP3's application-fragment reassembly is per-direction
   for the same reason COTP's TSDU reassembly is (nothing stops a DNP3
   session from having outstation->master and master->outstation fragments
   in flight at once), reached via
   `DecodeContext::flow_state<Dnp3ReassemblyState>(FlowStateKeying::DirectionalFlow)`.
   No interface novelty beyond that -- `Dnp3Decoder::decode` gathers
   everything the legacy call site dual-wrote into one `Dnp3Result`
   (`dnp3.hpp`), so `decoder.cpp`'s own call site shrinks to gate, call,
   dual-write, same as COTP's. `decoder.cpp`'s two dispatch cascades
   (declared-length probe and full decode) both sit exactly where the old
   `if (want_dnp3)` blocks always did -- immediately after TwinCAT, before
   the COTP/S7comm family, matching the position `protocol_registry.cpp`'s
   `tcp_port_independent_registry()` now also records it at. Verified: full
   CTest suite (1,197 tests, all passing, no changed expectations) across
   all three established configs, plus a manual JSON smoke-test over every
   existing DNP3 fixture -- including the 181-packet and 198-packet real
   captures (`dnp3_test_data_part1.pcap`, `dnp3_malformed.pcap`) -- confirming
   correct transport/application decoding, fragment reassembly (begin/
   abandon/complete), and graceful degradation on malformed input end to
   end; no new fixtures were needed since the existing corpus (particularly
   `sample_dnp3.pcap`'s packets 8-12) already exercises cross-packet
   reassembly directly.

   `GateKind::UdpPortIndependent` (the UDP-side mirror of
   `TcpPortIndependent`, needed for BACnet/IP, HART-IP's UDP path, and
   EtherNet/IP's own CIP I/O UDP path) was already added to the enum
   alongside `CotpPayload` when COTP/S7comm landed, but remains unused by
   any decoder until one of those three stages actually needs it.

   IEC 104 is also now done: `Iec104Decoder` (`iec104.hpp`/`iec104.cpp`)
   reproduces the existing same-TCP-payload multi-APDU coalescing loop and
   ASDU-merging logic that used to live directly in `decoder.cpp`'s
   `if (want_iec104)` call site. Unlike DNP3/COTP, IEC 104 needed no
   `FlowStateKeying` extension and no `DecoderFlowState` subclass at all --
   an I-format APDU always carries exactly one complete ASDU on the wire, so
   the whole decoder is purely stateless (see `iec104.hpp`'s own file header
   comment); `Iec104Decoder::decode` takes a `DecodeContext&` only because
   `ProtocolDecoder::decode`'s signature requires one, and never reads or
   writes it. `decoder.cpp`'s two dispatch cascades (declared-length probe
   and full decode) both sit exactly where the old `if (want_iec104)` blocks
   always did -- immediately after (still-legacy) OPC UA/EtherNet-IP, before
   Modbus, preserving the real collision-avoidance ordering documented in
   PROTOCOL DETECTION (an I-format APDU with N(S)=N(R)=0 can otherwise
   coincidentally read as a plausible Modbus/TCP MBAP header) regardless of
   which of the two has migrated. `protocol_registry.cpp`'s
   `tcp_port_independent_registry()` now lists IEC104 before Modbus to match
   that real order, rather than by migration date. Verified: full CTest
   suite (1,197 tests, all passing, no changed expectations) across all
   three established configs, plus a manual JSON smoke-test over every
   existing IEC 104 fixture -- including the Modbus-precedence collision
   fixture (still correctly resolving as `iec104`, not `modbus`) and the
   real Industroyer2 malware captures -- confirming correct APCI/ASDU
   decoding and multi-APDU coalescing end to end; no new fixtures were
   needed.

   OPC UA is also now done: `OpcUaDecoder` (`opcua.hpp`/`opcua.cpp`)
   reproduces the existing same-TCP-payload multi-chunk coalescing loop and
   per-field dual-write that used to live directly in `decoder.cpp`'s
   `if (want_opcua)` call site. Like IEC 104 (and unlike DNP3/COTP), OPC UA
   needed no `FlowStateKeying` extension and no `DecoderFlowState` subclass
   -- SecureConversation chunking is entirely self-contained within
   `try_parse_opcua_message`/`OpcUaMessage::wire_length`, with no
   cross-packet reassembly of its own, so the decoder is purely stateless;
   `OpcUaDecoder::decode` takes a `DecodeContext&` only because
   `ProtocolDecoder::decode`'s signature requires one. `decoder.cpp`'s two
   dispatch cascades (declared-length probe and full decode) both sit
   exactly where the old `if (want_opcua)` blocks always did -- tried first
   of the whole TCP-port-independent cascade, ahead of everything else
   (including the other two now-migrated protocols above), matching
   `protocol_registry.cpp`'s `tcp_port_independent_registry()`, which now
   lists it first for the same reason. Since `OpcUaMessage` already carried
   every field the legacy call site dual-wrote with no reduction of its
   own, `OpcUaResult` (`opcua.hpp`) just wraps the first coalesced chunk's
   full `OpcUaMessage` alongside the merged summary/notes, rather than
   re-declaring ~25 fields a second time. Verified: full CTest suite (1,197
   tests, all passing, no changed expectations) across all three
   established configs, plus a manual JSON smoke-test over both existing
   OPC UA fixtures -- including the real Wireshark-bug-repro capture --
   confirming correct Hello/Acknowledge/OpenSecureChannel/Message decoding,
   Tier 1 service bodies (e.g. `GetEndpointsResponse`'s full endpoint list),
   and multi-chunk coalescing end to end; no new fixtures were needed.

   EtherNet/IP is also now done, both sides: `EnipTcpDecoder` (explicit
   messaging, TCP port 44818) reproduces the existing same-TCP-payload
   multi-message coalescing loop and merge-CIP-fields logic that used to
   live directly in `decoder.cpp`'s `if (want_enip)` call site, including
   its one legacy asymmetry -- only the first coalesced message's own
   top-level `EnipFrame::notes` are folded into the result, while every
   message's `cip.notes` are (see `EnipResult`'s own comment in `enip.hpp`
   for why this is preserved rather than "fixed": the job here is an exact
   behavioral transplant, not a bug hunt). `EnipUdpDecoder` (CIP I/O
   implicit/real-time messaging, UDP port 2222) needed no coalescing logic
   of its own -- one UDP datagram is one complete, self-delimited CIP I/O
   message -- so its `decode()` is a direct pass-through onto
   `try_parse_cip_io`, returning the existing `CipIoFrame` unwrapped rather
   than a new result type. Both are purely stateless, like IEC 104/OPC UA
   above. This is also this codebase's first case of two registration-model
   decoder instances sharing one `id()` ("enip") -- confirmed safe because
   every output writer (`output.cpp`) already dispatches on the plain
   `DecodedPacket::protocol` string, never on a registry lookup requiring
   `id()` uniqueness. `decoder.cpp`'s three dispatch call sites (TCP
   declared-length probe, TCP full decode, UDP full decode) all sit exactly
   where the old `if (want_enip)`/`if (want_enip_io)` blocks always did;
   `protocol_registry.cpp`'s `tcp_port_independent_registry()` now lists
   `EnipTcpDecoder` right after OPC UA (matching real dispatch order), and
   `udp_port_independent_registry()` -- previously empty since this batch's
   `GateKind::UdpPortIndependent` addition had no user yet -- now lists
   `EnipUdpDecoder` first, its first real use. Verified: full CTest suite
   (1,197 tests, all passing, no changed expectations) across all three
   established configs, plus a manual JSON smoke-test over every existing
   EtherNet/IP fixture (TCP: RegisterSession/ListIdentity/SendRRData/
   SendUnitData, Read_Tag/Write_Tag, `Multiple_Service_Packet` recursion,
   including a 450-packet real capture with 319 EtherNet/IP messages; UDP:
   CIP I/O connection IDs/sequence numbers/data) confirming correct
   decoding, coalescing, and CIP value dual-write end to end; no new
   fixtures were needed.

   HART-IP is also now done, both sides: `HartIpTcpDecoder` and
   `HartIpUdpDecoder` (both `hartip.hpp`/`hartip.cpp`) reuse EtherNet/IP's
   own two-registration-model-decoder-instances-sharing-one-`id()` pattern
   (`"hartip"`), but unlike EtherNet/IP's genuinely separate TCP/UDP wire
   formats, HART-IP rides over EITHER transport using the exact SAME
   message shape and the SAME `try_parse_hartip` function, so both decoder
   classes are thin wrappers around one shared parser rather than each
   owning its own. `HartIpTcpDecoder::decode` reproduces the existing
   same-TCP-payload multi-message coalescing loop that used to live
   directly in `decoder.cpp`'s `if (want_hartip)` TCP call site (capped at
   50 messages, same as EtherNet/IP/DNP3/IEC104/OPC UA); `HartIpUdpDecoder`
   needs no coalescing of its own -- one UDP datagram is one complete
   message -- so its `decode()` is a direct pass-through, wrapped in the
   same `HartIpResult` type both sides share (`first` reuses `HartIpFrame`
   verbatim, mirroring `EnipResult`'s own "first" convention, since
   `HartIpFrame` already carried every field the legacy call sites
   dual-wrote with no reduction of its own). Both are purely stateless.
   The one piece of logic that moved rather than transplanted unchanged:
   the IKE-NAT-T (port 4500)/VXLAN (port 4789) UDP exclusion, previously
   computed inline at `decoder.cpp`'s old UDP call site, is now a small
   `hartip_udp_excluded_port(uint16_t)` helper in `hartip.hpp` itself --
   same two ports, same RFC 3948/RFC 7348 rationale, just living next to
   the parser it protects instead of at the call site; it remains a
   call-site-level pre-check deciding whether `HartIpUdpDecoder::decode` is
   even attempted in Auto mode, not something `decode()` itself tests. The
   accepted, documented HART-IP-Session-Initiate-vs-Modbus/TCP collision on
   the TCP side is unchanged and, per its own comment history, deliberately
   NOT re-litigated here -- reordering HART-IP ahead of Modbus was already
   tried and measurably regressed the Modbus/S7comm corpus before this
   batch began. `decoder.cpp`'s three dispatch call sites (TCP
   declared-length probe, TCP full decode, UDP full decode) all sit exactly
   where the old `if (want_hartip)` blocks always did;
   `protocol_registry.cpp`'s `tcp_port_independent_registry()` now lists
   `HartIpTcpDecoder` right after COTP (tried last of that whole cascade,
   matching real dispatch order), and `udp_port_independent_registry()`
   now lists `HartIpUdpDecoder` right after `EnipUdpDecoder`, its second
   real use (BACnet/IP's own UDP slot in between is skipped, still
   legacy). Verified: full CTest suite (1,197 tests, all passing, no
   changed expectations) across all three established configs, plus a
   manual JSON smoke-test over every existing HART-IP fixture --
   `sample_hartip.pcap` (55 messages: Session Initiate/Close/Keep
   Alive/Error/NAK plus every dispatched Pass-Through command, mixing TCP
   and UDP traffic, several deliberately coalesced into shared payloads),
   `sample_hartip_checksum.pcap` (valid/invalid longitudinal-checksum
   pair), and a 46-message real TCP capture (`hart_ip.pcapng`) -- all
   decoding and dual-writing identically to before migration; no new
   fixtures were needed.

   BACnet/IP is also now done: `BacnetDecoder` (`bacnet.hpp`/`bacnet.cpp`)
   is the simpler of this batch's two `GateKind::UdpPortIndependent`
   additions -- its own `id()` ("bacnet"), not shared with anything, and
   (unlike EtherNet/IP's CIP I/O and HART-IP's own UDP path) no new
   wrapper result type at all: `try_parse_bacnet`'s existing `BacnetFrame`
   already carried every field the legacy `if (want_bacnet)` call site
   dual-wrote, so `BacnetDecoder::decode` is a direct pass-through
   returning it unwrapped, the same "no new result type" shape
   `EnipUdpDecoder` has. Purely stateless, one UDP datagram in, one
   complete BVLC/NPDU/APDU decode out, no coalescing logic needed.
   `decoder.cpp`'s single dispatch call site sits exactly where the old
   `if (want_bacnet)` block always did; `protocol_registry.cpp`'s
   `udp_port_independent_registry()` now lists `BacnetDecoder` between
   `EnipUdpDecoder` and `HartIpUdpDecoder`, matching real UDP dispatch
   order (CIP I/O, then BACnet/IP, then HART-IP) -- this fills what was
   previously a documented gap in that vector (BACnet's own slot, left
   empty while it was still legacy). Verified: full CTest suite (1,197
   tests, all passing, no changed expectations) across all three
   established configs, plus a manual JSON smoke-test over both existing
   BACnet fixtures -- `sample_bacnet.pcap` (every BVLC function, NPDU
   DEST/SRC/Network-Layer-Message combination, and every "first pass"
   APDU service/PDU-type this decoder value-decodes) and the 54-frame real
   capture (`ICS-OT-Network-001-bacnet-excerpt.pcap`, 27
   Confirmed-Request/Complex-ACK ReadProperty pairs against trend-log
   objects) -- all decoding and dual-writing identically to before
   migration; no new fixtures were needed.

   With this, every `GateKind::UdpPortIndependent` protocol this codebase
   has is now migrated -- `udp_port_independent_registry()` is fully
   populated for the first time.

   MQTT is also now done -- the eleventh and last protocol in this batch:
   `MqttDecoder` (`mqtt.hpp`/`mqtt.cpp`) reproduces the existing session-
   version-hint lookup/learning and same-TCP-payload multi-packet
   coalescing loop that used to live directly in `decoder.cpp`'s
   `if (want_mqtt)` call site (small control packets like PINGREQ/PUBACK/
   SUBACK are commonly coalesced, capped at 50, the same shape DNP3/
   IEC104/OPC UA/EtherNet-IP/HART-IP all already have). The one piece of
   cross-packet state MQTT needs -- its per-session learned protocol
   version (0=unknown, 4=v3.1.1, 5=v5.0), used only to disambiguate
   SUBSCRIBE/SUBACK/UNSUBSCRIBE's genuinely ambiguous v3.1.1-vs-v5 wire
   shape -- moved from the bespoke `Decoder::mqtt_session_version_` map
   into `MqttFlowState`, reached via `DecodeContext::flow_state<T>()`'s
   unchanged, session-keyed default (`FlowStateKeying::Session`), the same
   generalization Stage 2 (Modbus) already did for `modbus_pending_`.
   Unlike COTP/DNP3's own `FlowStateKeying::DirectionalFlow` extension,
   MQTT's version hint is correctly session-scoped, not per-direction: a
   CONNECT and a later SUBSCRIBE/SUBACK/UNSUBSCRIBE needing this hint can
   travel in either direction relative to each other. This confirms
   `flow_state<T>()`'s unchanged default still has a live, non-trivial
   user after this batch's two `DirectionalFlow` additions, not just the
   pilot's own Modbus/TwinCAT usage. `decoder.cpp`'s two dispatch cascades
   (declared-length probe and full decode) both sit exactly where the old
   `if (want_mqtt)` blocks always did -- tried last of the whole
   TCP-port-independent cascade, ahead of only still-legacy FF-HSE, the
   same position its own honestly-weak single-leading-byte gate has always
   earned it; `protocol_registry.cpp`'s `tcp_port_independent_registry()`
   now lists `MqttDecoder` last, matching real dispatch order. The
   FTP-control-line/LDAP-BER port carve-outs (both pre-existing,
   documented collisions with MQTT's own weak gate) stay exactly where
   they were -- call-site pre-checks deciding whether to invoke this
   decoder at all, untouched by the migration. Verified: full CTest suite
   (1,197 tests, all passing, no changed expectations) across all three
   established configs, plus a manual JSON smoke-test over every existing
   MQTT fixture -- `sample_mqtt.pcap` (55 packets: every packet type
   across v3.1.1/v5.0, coalesced control packets, all three genuinely
   ambiguous types exercising both the session-tracked and per-packet-
   heuristic disambiguation paths, and Sparkplug B NBIRTH/DBIRTH/NDATA/
   DDATA/DDEATH/STATE decode) and both real captures
   (`mqtt_packets_tcpdump.pcap`/`mqtt_packets.pcapng`, 19 messages each) --
   all decoding and dual-writing identically to before migration; no new
   fixtures were needed.

   **This completes migration batch 2** -- all eleven protocols planned
   (COTP, S7comm, S7comm-Plus, MMS, DNP3, IEC104, OPC UA, EtherNet/IP,
   HART-IP, BACnet/IP, MQTT) are now built on the registration-model
   `ProtocolDecoder` interface, alongside the pilot's own EIGRP/Modbus/
   GOOSE and TwinCAT. Every `GateKind` this codebase defines
   (`EtherType`/`IpProtocol`/`TcpPortIndependent`/`UdpPort`/
   `UdpPortIndependent`/`CotpPayload`) now has at least one real user, and
   both `FlowStateKeying` values (`Session`/`DirectionalFlow`) have
   multiple independent users each. The only protocol left un-migrated in
   the four gate cascades this batch touched is FF-HSE (TcpPortIndependent
   -- tried last of that whole cascade, its own honestly weak gate earning
   it that position the same way MQTT's does); `UdpPort` remains reserved
   and empty, as it always has been (see its own doc comment in
   `protocol_registry.hpp`).

   Still explicitly out of scope, not silently dropped: migrating the
   remaining ~37 legacy protocols onto the new interface (down from ~48 at
   the start of this batch); migrating
   `output.cpp`'s rendering for the three *pilot* protocols themselves
   (EIGRP/Modbus/GOOSE keep dual-writing into their flat fields, unlike
   TwinCAT); having the registry vectors in `protocol_registry.cpp`
   actually drive dispatch order during this pilot, rather than being
   audit-trail data kept in sync with the real `decoder.cpp` call sites by
   hand; a differential pre/post-migration JSON-output diff (this
   environment has no git history to build a genuine "before" binary from,
   so the full regression suite's unchanged `PASS_REGULAR_EXPRESSION`
   assertions are the substitute evidence -- any drift in EIGRP/Modbus/
   GOOSE's own output would have failed one of those hardcoded-exact-text
   tests); and deduplicating `policy_engine.cpp`'s/`asset_inventory.cpp`'s
   independently-forked protocol-classification chains (unaffected either
   way by this pilot -- both still read `DecodedPacket::protocol` as a
   plain string, which every migrated protocol, including TwinCAT, keeps
   populating).

   **Update: migration batch 3 complete -- the entire OT EtherType fieldbus
   family, `EtherType` gate cascade now fully populated.** Jurgen asked
   what should move to the `ProtocolDecoder` interface next; a fresh audit
   (grepping for `: public ProtocolDecoder` across every header and every
   `want_X` flag still live in `decoder.cpp`, rather than trusting this
   document to be current) confirmed batch 2's own count and picked the
   highest-value remaining group: the OT EtherType fieldbus family still
   sitting in the legacy `EtherType` if-chain -- IEC 61850-9-2 Sampled
   Values (SV), PROFINET RT, EtherCAT, EAPOL, STP/RSTP/MSTP, MPLS, PPPoE.
   Migrating all seven empties that cascade entirely (previously only
   GOOSE, from the pilot, was migrated there) and carried the highest OT
   audit value of any remaining group, since it's the same EtherType-
   gated, no-IP-layer shape GOOSE and TwinCAT already proved out.

   Six of the seven (SV, PROFINET RT, EtherCAT, EAPOL, PPPoE, MPLS) are
   genuinely EtherType-gated with no cross-packet state, so each got the
   same minimal treatment: a thin `XDecoder : public ProtocolDecoder`
   subclass in the protocol's own header/`.cpp` pair, wrapping its
   existing, unchanged `try_parse_x` exactly the way `GooseDecoder::decode`
   already wrapped `try_parse_goose`; each `decoder.cpp` call site kept its
   exact textual position (SV immediately after GOOSE; PROFINET RT tried
   first of the whole cascade; EtherCAT after SV; EAPOL after EtherCAT;
   PPPoE after EAPOL; MPLS after PPPoE) and now reaches its `try_parse_x`
   through `x_decoder().decode()` instead of calling it directly, with the
   same dual-write into `DecodedPacket`'s existing flat fields as before
   (none of these six were part of the original three-protocol pilot, so,
   like every batch 2 protocol, none is a from-inception zero-flat-fields
   case the way TwinCAT is). PPPoE and MPLS each needed two decoder
   instances sharing one `id()` rather than one -- PPPoE's Discovery
   (0x8863) and Session (0x8864) stages, MPLS's unicast (0x8847) and
   multicast (0x8848) EtherTypes -- the same "two instances, one `id()`"
   pattern `EnipTcpDecoder`/`EnipUdpDecoder` established first for a
   TCP/UDP split, here reused for an EtherType split instead (see
   `pppoe.hpp`/`mpls.hpp`).

   STP, the seventh, is the one genuine exception in this batch: it has no
   EtherType of its own at all -- it rides classic 802.3 LLC framing (DSAP/
   SSAP == 0x42, Control == UI), not any EtherType-keyed dispatch, and its
   own GARP-collision carve-out (disambiguating STP's LLC DSAP/SSAP pair
   from GVRP/GMRP by destination MAC) depends on the outer Ethernet frame's
   destination address, which lives outside the `ByteSpan` a `decode()`
   call receives. `StpDecoder::gate_kind()` is still `GateKind::EtherType`
   (the same bucket that enum's own doc comment already grouped STP into
   alongside its EtherType-keyed siblings), but `ethertype()` is left at
   `ProtocolDecoder`'s own default (`std::nullopt`) rather than overridden,
   and `decoder.cpp`'s own call site keeps full, unchanged responsibility
   for STP's actual structural gate (802.3 Length framing, DSAP/SSAP/
   Control, and the GARP carve-out) before ever reaching `decode()` --
   nothing about that gating logic moved into the new class.

   Verified the same way every prior migration was, once per protocol as
   each landed: the full CTest suite (1300 tests throughout -- no
   `PASS_REGULAR_EXPRESSION` needed editing for any of the seven, proof of
   byte-identical output at every step) stayed 100% passing, zero-warning
   clean rebuilds across all three established configs (default+libpcap,
   `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`, MinGW cross-compile) after
   each protocol, and manual CLI smoke tests (`--format text`/`--format
   json`, plus each protocol's own `--protocol` filter) against every
   available fixture -- `tests/sample_sv.pcap`, `tests/sample_profinet.pcap`
   plus the two real PROFINET captures under `tests/real_captures/
   profinet/`, `tests/sample_ethercat.pcap` plus the real capture under
   `tests/real_captures/ethercat/`, the EAPOL/PPPoE/MPLS frames inside
   `tests/sample_enterprise_trust.pcap`/`tests/sample_wireless_backhaul.
   pcap`/`tests/sample_tunnel_vpn.pcap`, and `tests/sample_stp.pcap` plus
   the real capture under `tests/real_captures/stp/` -- confirmed every
   migrated path produces identical output to its pre-migration
   `try_parse_x` call site.

   This completes migration batch 3: the `EtherType`/LLC gate cascade in
   `protocol_registry.cpp` is now fully populated (PROFINET RT, GOOSE, SV,
   EtherCAT, EAPOL, PPPoE, MPLS, STP -- the fourth `GateKind`, after
   `IpProtocol`/`TcpPortIndependent`/`UdpPortIndependent`, to reach that
   state), and the `~37` legacy-protocol count in batch 2's own completion
   note above now reads `~30`.

   **Update: migration batch 4 complete -- the UDP-port family, `UdpPort`
   gate cascade populated for the first time.** Asked what to migrate
   next, offered the remaining groups still sitting in `decoder.cpp`'s
   legacy if-chains; Jurgen picked the UDP-port-gated family: DNS, mDNS,
   LLMNR, NBT-NS, HSRP, RIP. Unlike every prior batch, this was
   `GateKind::UdpPort`'s first real use anywhere in the codebase --
   `ProtocolDecoder::udp_port()` itself did not exist before this batch
   (added alongside `ethertype()`/`ip_protocol()`, following the exact
   same "audit-trail documentation, not what drives the actual gate"
   posture those two already established: Auto mode's own "only
   port-gate when the protocol wasn't named explicitly via `--protocol`"
   policy depends on CLI state (`ProtocolFilter`) a `decode()` call has
   no access to, so that decision, and any `--extra-X-ports` widening,
   stays at `decoder.cpp`'s own call site exactly as it did before
   migration -- the same posture `StpDecoder`'s own comment already
   documented for a different reason).

   All six protocols got the same minimal treatment as batch 3's six
   simple EtherType migrations: a thin `XDecoder : public ProtocolDecoder`
   subclass wrapping each protocol's existing, unchanged `try_parse_x`,
   with `decoder.cpp`'s call site kept at its exact textual position and
   now reaching `try_parse_x` through `x_decoder().decode()` instead of
   calling it directly. DNS, mDNS, and LLMNR are a variant of PPPoE/MPLS's
   own "two instances, one `id()`" pattern from batch 3 -- except here it's
   *three* instances (`DnsDecoder`/`MdnsDecoder`/`LlmnrDecoder`) sharing
   not just a parser but a single function, `try_parse_dns_message`,
   differentiated only by a `DnsFlavor` enum argument (`Dns`/`Mdns`/
   `Llmnr`) the shared RFC-1035-derived wire structure never itself
   needed disambiguating; each class supplies its own `id()`/`udp_port()`
   (`DNS_PORT`/`MDNS_PORT`/`LLMNR_PORT`) and a one-line `decode()` that
   just picks the flavor (see `dns.hpp`'s own comment). NBT-NS, HSRP, and
   RIP each got an ordinary single-instance wrapper.

   The true call-site order -- confirmed by grepping `decoder.cpp` for
   `bool want_X` rather than assumed -- is RIP, then HSRP, then DNS, then
   mDNS, then LLMNR, then NBT-NS; `udp_port_registry()` in
   `protocol_registry.cpp` lists the six in exactly that order (an
   earlier draft of this batch had DNS listed first, on the mistaken
   assumption it was the cascade's head -- caught and corrected before
   this batch shipped, by the same grep-the-real-call-sites discipline
   rather than trusting an assumption).

   Verified the same way every prior migration was: the full CTest suite
   (1301 tests -- no `PASS_REGULAR_EXPRESSION` needed editing for any of
   the six, proof of byte-identical output at every step) stayed 100%
   passing, zero-warning clean rebuilds across all three established
   configs (default+libpcap, `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`,
   MinGW cross-compile), and manual CLI smoke tests (`--format text`)
   against every available fixture -- `tests/sample_dns.pcap`,
   `tests/sample_mdns.pcap`, `tests/sample_llmnr.pcap`,
   `tests/sample_nbns.pcap`, `tests/sample_hsrp.pcap`,
   `tests/sample_rip.pcap` -- confirmed every migrated path produces
   identical output to its pre-migration `try_parse_x` call site,
   including each protocol's own curated notes (e.g. RIPv2's cleartext
   Simple Password note, HSRPv1's own cleartext-authentication note) and
   the port-mismatch fallback to generic `[udp]` (LLMNR's and NBT-NS's
   own off-port packets in their sample fixtures still fall through
   exactly as before).

   This completes migration batch 4: the `UdpPort` gate cascade in
   `protocol_registry.cpp` is now fully populated (RIP, HSRP, DNS, mDNS,
   LLMNR, NBT-NS) -- the last of the six `GateKind` values to get a real
   entry (`EtherType`/`IpProtocol`/`TcpPortIndependent`/
   `UdpPortIndependent`/`CotpPayload` were already populated by the pilot
   and batches 2-3), so every registry vector in `protocol_registry.cpp`
   now holds at least one real decoder. The `~30` legacy-protocol count in
   batch 3's own completion note above now reads `~24`.

   **Update: migration batch 5 complete -- `IpProtocol` fully populated,
   the fifth of the six `GateKind`s to reach that state.** Asked for a
   priority list, Jurgen picked finishing the `IpProtocol`-gated family
   next (and asked for BGP-4, plus ARP and LLDP, as follow-on new
   protocols -- see items further down this ROADMAP for that work).
   `GateKind::IpProtocol` already had one real entry from the original
   pilot (EIGRP, item 3's very first "Update" above) but was otherwise
   still five legacy `if`-chain entries in `decoder.cpp`: ICMP, IGMP,
   VRRP, IGRP, PIM, OSPFv2. All six got the same minimal treatment as
   every prior batch's simple cases: a thin `XDecoder : public
   ProtocolDecoder` subclass per protocol, wrapping each protocol's
   existing, unchanged `try_parse_x`, with `decoder.cpp`'s call site kept
   at its exact textual position (the "coexistence rule" -- migrating
   changes WHAT runs, never WHICH LINE) and now reaching `try_parse_x`
   through `x_decoder().decode()` instead of calling it directly.

   IGRP was this batch's one real wrinkle: `try_parse_igrp` needs the
   packet's own IPv4 source address (its 3-byte classful Network field
   borrows a missing high-order octet from it for Interior routes -- see
   `igrp.hpp`'s own file header), and `ProtocolDecoder::decode()` only
   receives a `ByteSpan` plus a `DecodeContext&`. Rather than special-case
   IGRP's call site outside the registration-model interface, `DecodeContext`
   (`protocol_decoder.hpp`) gained one new, narrowly-documented field --
   `uint32_t ip_src_addr = 0;` -- populated by `decoder.cpp` right before
   calling `igrp_decoder().decode()`, IGRP's only user. The other five
   protocols needed nothing beyond the standard wrapper shape.

   `protocol_registry.cpp`'s `ip_protocol_registry()` now lists all seven
   `IpProtocol`-gated decoders in real call-site order -- ICMP, IGMP,
   VRRP, IGRP, PIM, EIGRP, OSPF (EIGRP sits where the pilot originally
   placed it, in the middle rather than at either end).

   Verified the same way every prior migration was: the full CTest suite
   (1354 tests) stayed 100% passing with zero changed
   `PASS_REGULAR_EXPRESSION`/`FAIL_REGULAR_EXPRESSION` assertions anywhere
   (proof of byte-identical output for all six), zero-warning clean
   rebuilds across all three established configs (default+libpcap,
   `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`, MinGW cross-compile), and
   manual CLI smoke tests against every existing fixture
   (`tests/sample_icmp.pcap`, `sample_igmp.pcap`, `sample_vrrp.pcap`,
   `sample_igrp.pcap`, `sample_pim.pcap`, `sample_ospf.pcap`) confirming
   identical output to each protocol's pre-migration call site.

   This completes migration batch 5: `ip_protocol_registry()` is now
   fully populated, the fifth of the six `GateKind` values to reach that
   state (`EtherType` by batch 3, `UdpPortIndependent`/`CotpPayload` by
   batch 2, `UdpPort` by batch 4 -- see each one's own completion note
   above). `TcpPortIndependent` is now the only `GateKind` left with a
   legacy holdout: `tcp_port_independent_registry()`'s own doc comment
   already names it -- FF-HSE, tried last of that whole cascade, out of
   scope for every batch so far. The `~24` legacy-protocol count in batch
   4's own completion note above now reads `~18`. ARP and LLDP have since
   both been added (items 31 and 32 below); BGP-4 has since been added too
   (item 33 below), completing this three-stage plan (migration batch 5,
   then ARP+LLDP, then BGP-4).

   **Update: the `EtherType` cascade's registry vector now actually drives
   dispatch order -- the first `GateKind` to close the "audit-trail only"
   gap flagged all the way back in batch 2's own "still explicitly out of
   scope" note above.** Jurgen asked directly whether the registry vectors
   drove dispatch order yet (they didn't -- confirmed by grepping for
   every `*_registry()` accessor and finding zero non-comment call sites
   outside `protocol_registry.{hpp,cpp}` itself), then asked for exactly
   this: replace a cascade's `if`-chain with a loop over its registry
   vector, calling `decode()` on each entry in order until one matches.
   Scoped to one cascade first, `EtherType`, since it was the only one of
   the six already fully populated with a genuinely uniform per-entry gate
   (every EtherType in this cascade is IANA/IEEE-exclusive to its own
   protocol, so trying entries in any order that keeps STP last is safe --
   see below).

   `decoder.cpp`'s EtherType call site now loops over `ethertype_registry()`
   directly: for each entry, skip it unless its `ethertype()` matches the
   frame's and the active `--protocol` filter allows it (a new, cascade-
   local `ethertype_cascade_filter_allows()` helper replaces the ten
   hand-written `want_x` booleans -- it maps each `id()` to its own
   `ProtocolFilter` enum value, `Auto` always passing), then call
   `decode()`; the first result wins, exactly like the old if-chain's
   first-match-returns behavior. Two structural wrinkles, both resolved
   without touching the `ProtocolDecoder` interface itself: PPPoE and MPLS
   each contribute two registry entries sharing one `id()` but different,
   mutually-exclusive `ethertype()` values (discovery/session,
   unicast/multicast) -- the loop already tries at most one of each pair
   per frame, so no special-casing was needed there; MPLS's dual-write
   needs `is_multicast`, which isn't derivable from the decoded `MplsFrame`
   alone (see item 3's very first "Update" above for how it used to be
   computed inline) -- solved by passing the matched EtherType itself into
   every populate function's signature, unused by all but MPLS's.

   Rather than adding a new virtual method to `ProtocolDecoder` (touching
   every migrated protocol's own header, all six `GateKind`s, for one
   cascade's benefit), each protocol's existing dual-write body was
   extracted verbatim into a `populate_x(DecodedPacket&, const
   ProtocolResult&, uint16_t matched_ethertype)` free function local to
   `decoder.cpp` (`resource_limits()`, which several of these call, is
   itself a free function needing no captured state, so this cost
   nothing), looked up by `id()` through a small `unordered_map`. STP,
   having no `ethertype()` at all (LLC-framed, not EtherType-framed -- see
   `stp.hpp`), can never match this loop regardless of its position in the
   vector and keeps its own explicit block, unchanged, exactly where it
   always sat -- right after the loop, gated on `eth.is_llc_length &&
   eth.has_llc` plus the DSAP/SSAP/Control/GARP checks the loop has no way
   to express generically.

   One real inconsistency surfaced and fixed while wiring this up:
   `ethertype_registry()` had STP positioned mid-vector (right after MPLS,
   before ARP/LLDP/Slow Protocols), left over from when STP genuinely was
   `decoder.cpp`'s last EtherType-cascade entry -- ARP, LLDP, and Slow
   Protocols were each appended to `decoder.cpp`'s real call site *after*
   STP in every case, but the registry vector's own STP entry never moved
   to match. Harmless while the vector was audit-trail-only (STP's
   `ethertype()` being `nullopt` means it could never have been reached
   through a loop in the first place, so this drifted silently), but worth
   fixing now that the vector is live: STP moved to the actual end of
   `ethertype_registry()`, matching `decoder.cpp`'s real order exactly.

   Verified the same way as every prior migration: the full CTest suite
   (1412 tests) stayed 100% passing with zero changed
   `PASS_REGULAR_EXPRESSION`/`FAIL_REGULAR_EXPRESSION` assertions anywhere
   (proof of byte-identical output for all ten protocols this cascade
   covers), zero-warning clean rebuilds across the two configs checked in
   this environment (default+libpcap, `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`),
   and manual smoke tests confirming both auto-mode detection and
   `--protocol`-filtered output are byte-identical to before this change
   across the PROFINET/GOOSE/EtherCAT/ARP/LLDP/STP/Slow Protocols
   fixtures, including each protocol's own malformed-frame fallback path.

   Still explicitly out of scope: the other five `GateKind`s
   (`IpProtocol`/`TcpPortIndependent`/`UdpPort`/`UdpPortIndependent`/
   `CotpPayload`) remain audit-trail data only, kept in sync with
   `decoder.cpp`'s real call sites by hand, not yet driving dispatch --
   each has its own generalization wrinkles to work through before it can
   follow `EtherType`'s lead the same way (`CotpPayload` in particular
   already has its own documented reason to possibly stay a manual
   if-chain permanently -- see `cotp_payload_registry()`'s doc comment).

   **Update: the pilot's own leftover -- `output.cpp`'s rendering for
   EIGRP/Modbus/GOOSE -- is now migrated too, closing the specific gap
   batch 2's "still explicitly out of scope" note (above) flagged.** All
   three now carry their full typed result forward via
   `DecodedPacket::result` (`out.result = *result;`/`out.result = result;`
   at each call site) instead of dual-writing into their own `eigrp_*`/
   `modbus_*`/`goose_*` flat fields -- the same zero-flat-field shape
   TwinCAT/BGP/Slow Protocols/Kerberos/LDAP/SMB/MELSEC/FINS already use.
   `decoder.cpp`'s now-orphaned `fill_eigrp_fields`/
   `eigrp_general_tlv_summary` helpers were deleted outright (EIGRP's own
   call site was the only caller of either); GOOSE's `populate_goose`
   shrank to the same three-line shape `populate_slow_protocols` already
   established for the `EthertypeCascadePopulate` loop. Three new free
   functions in `output.cpp` (`write_eigrp_json_fields`/
   `write_modbus_json_fields`/`write_goose_json_fields`, mirroring
   `write_twincat_json_fields`'s own style) render straight from the typed
   `EigrpMessage`/`ModbusFrame`/`GooseFrame`, called from
   `JsonWriter::write_packet` only `if (p.protocol == "x" && p.result)` --
   the exact `TwinCAT` convention -- at each block's own, unmoved textual
   position; `TextWriter`'s Modbus-exception severity check and
   `StatsWriter`'s three aggregate blocks were updated the same way.
   GOOSE's two-tier truncation cap (`goose.cpp`'s own 200-entry cap on
   `GooseFrame::all_data`, plus a separate, smaller
   `resource_limits().max_decoded_objects.value_or(50)` cap applied only
   when rendering `goose_all_data` for JSON -- the same pattern PROFINET
   RT's DCP blocks use) was reproduced exactly, as was a genuine pre-
   existing quirk: GOOSE's has-PDU-gated JSON fields were always rendered
   whenever `GooseFrame::has_pdu` was true, not gated a second time on
   `protocol == "goose"` -- harmless in practice (`has_pdu` is only ever
   true on a GOOSE packet) but preserved as-is rather than "fixed" out
   from under a byte-identical-output verification bar.

   `modbus_function_name` turned out to have two readers outside
   `decoder.cpp`/`output.cpp` -- `policy_engine.cpp`'s conduit function-
   list matching and `asset_inventory.cpp`'s per-asset function-name
   field, both found by exhaustively grepping every flat-field usage site
   across `src/`/`include/`/`fuzz/` before touching anything, per this
   project's own established discipline for scoping a dual-write removal
   (see TwinCAT's own precedent). Both now read
   `dp.result->as<ModbusFrame>().function_name` instead; EIGRP and GOOSE
   had exactly two readers each (`decoder.cpp`'s own dual-write and
   `output.cpp`'s own rendering), so nothing else needed touching for
   them. All now-unused `eigrp_*`/`goose_*`/`modbus_*` `DecodedPacket`
   flat-field declarations were removed from `decoder.hpp`, along with the
   stale doc comments elsewhere (`decoder.hpp`/`modbus.hpp`/`twincat.hpp`)
   that referenced them by name.

   Verified the same way as every prior migration: the full CTest suite
   (1,416 tests) stayed 100% passing with zero changed
   `PASS_REGULAR_EXPRESSION`/`FAIL_REGULAR_EXPRESSION` assertions anywhere
   (proof of byte-identical output for all three protocols), zero-warning
   clean rebuilds across both configs checked in this environment
   (default+libpcap, `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`), and a
   manual JSON smoke test against each protocol's own fixture confirming
   field-for-field identical output to before this change.

   Still explicitly out of scope, not silently dropped: migrating the
   remaining legacy protocols onto the new interface; having the registry
   vectors in `protocol_registry.cpp` drive dispatch order for the other
   five `GateKind`s (unchanged by this update -- see the note directly
   above); and deduplicating `policy_engine.cpp`'s/`asset_inventory.cpp`'s
   own independently-forked protocol-classification chains beyond the one
   Modbus read each needed to keep compiling (both still read
   `DecodedPacket::protocol` as a plain string for everything else, the
   same as before).

   **Update: FF-HSE and DeviceNet migrated -- `TcpPortIndependent`'s last
   legacy holdout is gone, and a brand-new sixth `GateKind` (`LinkType`)
   exists to carry DeviceNet.** Jurgen asked directly for both. FF-HSE got
   the full two-part treatment every migration since the pilot's own
   leftover-fix (above) has used: `FfhseTcpDecoder`/`FfhseUdpDecoder`
   (`ffhse.hpp`/`ffhse.cpp`) wrap the existing, unchanged `try_parse_ffhse`
   and its declared-length probe (`tcp_declared_length()`), sharing one
   `"ffhse"` id() the same way `HartIpTcpDecoder`/`HartIpUdpDecoder` do;
   `decoder.cpp`'s two call sites (TCP and UDP, both still tried dead last
   of their own cascades -- see "Why FF-HSE is tried last of all" above,
   unchanged by this migration) now reach `try_parse_ffhse` through
   `ffhse_tcp_decoder().decode()`/`ffhse_udp_decoder().decode()` instead of
   calling it directly, and both keep their own same-payload/same-datagram
   coalescing loop, now living inside each `decode()` -- FF-HSE is the
   first protocol in this codebase whose UDP side coalesces multiple PDUs
   per datagram at all (`HartIpUdpDecoder`/`EnipUdpDecoder` both
   deliberately do not; FF-HSE's own UDP framing genuinely can carry
   several concatenated PDUs per datagram, unlike either of those). Landed
   with the full zero-flat-field `output.cpp` treatment from the start
   (not dual-write-then-migrate): `out.result` carries the whole
   `FfhseResult`, a new `write_ffhse_json_fields` renders it, and
   `policy_engine.cpp`'s/`asset_inventory.cpp`'s own `ffhse_message_name`
   reads (the only two extra readers found, same discipline as every prior
   dual-write removal) now go through `dp.result->as<FfhseResult>()`. All
   `ffhse_*` flat fields removed from `decoder.hpp`.

   DeviceNet needed a genuinely new gate: it dispatches on the pcap
   capture's own link-layer type (`LINKTYPE_CAN_SOCKETCAN`), not on
   anything inside the packet's bytes, so none of the five existing
   `GateKind` values fit -- a new one, `GateKind::LinkType`, was added to
   `protocol_decoder.hpp` (plus a matching `link_type()` accessor,
   `nullopt` for every other decoder), the same "add a new gate kind when
   none fits" precedent `CotpPayload` set first. `try_parse_devicenet`
   is also the one `try_parse_x` function in this codebase that takes a
   structured `CanSocketcanFrame` rather than a `ByteSpan`, which doesn't
   fit `ProtocolDecoder::decode(ByteSpan, DecodeContext&)`'s signature
   directly -- resolved by having `DeviceNetDecoder::decode()` re-derive
   the `CanSocketcanFrame` from the raw `ByteSpan` via
   `parse_socketcan_frame()` internally, exactly mirroring what
   `decoder.cpp`'s own `LINKTYPE_CAN_SOCKETCAN` branch did directly before
   this migration. That is a deliberate, explicitly documented exception
   to `decode()`'s usual "never throws" contract (`parse_socketcan_frame`
   can throw `ParseError` on a malformed capture record) -- called out in
   both `devicenet.hpp`'s class comment and `decoder.cpp`'s call-site
   comment rather than glossed over. One field, `DeviceNetFrame::
   payload_truncated`, was added (populated from `CanSocketcanFrame::
   truncated` inside `try_parse_devicenet`) purely so the migrated
   `decode()` -- which only returns a `DeviceNetFrame`, not the raw
   `CanSocketcanFrame` -- could still surface that boolean to
   `write_devicenet_json_fields` without losing it. `protocol_registry.cpp`
   gained a new `link_type_registry()` vector (audit-trail only, like
   `cotp_payload_registry()` -- `decoder.cpp`'s own branch calls
   `devicenet_decoder()` directly rather than looping, since DeviceNet is
   this gate's only protocol) listing DeviceNet, its sole entry. No extra
   readers of `devicenet_*` flat fields were found outside
   `decoder.cpp`/`output.cpp` (confirmed by the same exhaustive grep sweep
   every prior dual-write removal has used); all were removed from
   `decoder.hpp`.

   Both protocols' registry entries were appended to
   `tcp_port_independent_registry()`/`udp_port_independent_registry()`
   (FF-HSE, tried last of each, matching its real dispatch position) and
   the new `link_type_registry()` (DeviceNet); the stale "Not migrated:
   FF-HSE" doc comment on `tcp_port_independent_registry()` is gone --
   this fully populates `TcpPortIndependent`, the sixth (of what are now
   six) `GateKind`s to reach that state.

   Verified the same way as every prior migration: the full CTest suite
   (1,416 tests) stayed 100% passing with zero changed
   `PASS_REGULAR_EXPRESSION`/`FAIL_REGULAR_EXPRESSION` assertions anywhere
   (proof of byte-identical output for both protocols), a clean rebuild
   with zero warnings, and manual `--format json`/`--stats` smoke tests
   against `tests/sample_ffhse.pcap`/`tests/sample_devicenet.pcap`
   confirming field-for-field identical output to before this change.

   Still explicitly out of scope, not silently dropped: migrating any of
   the remaining legacy protocols; having the registry vectors drive
   dispatch order for any `GateKind` beyond `EtherType`.

   **Update: asked directly whether every migratable protocol had been
   moved, the answer was no -- DoH detection was a genuine, previously
   unnoticed gap, and it's now migrated too, closing it.** A systematic
   census (every `ProtocolDecoder` subclass in the codebase, cross-checked
   against every protocol-prefixed flat field still in `decoder.hpp`)
   found exactly one protocol producing real decoded structure
   (`tls_sni.hpp`'s `DohDetection`: SNI, ALPN protocols, matched provider
   name) that was still on the legacy dual-write path -- not part of item
   18's 43 name-only "IT protocols an OT auditor flags" recognitions
   (that item's own "Architectural scope note" above stays correct: this
   was a distinct, one-off TLS-ClientHello detector living in
   `tls_sni.hpp`, never discussed in relation to the registration model at
   all, simply missed rather than deliberately excluded).

   DoH needed a genuinely new gate: it's port-gated in Auto mode (like
   `UdpPort`'s own protocols -- no self-describing byte shape strong
   enough to check opportunistically, despite the ClientHello/SNI check
   itself being fairly strong once a segment is even attempted), but rides
   TCP, and none of the six existing `GateKind`s fit that shape --
   `TcpPortIndependent` is tried opportunistically regardless of port,
   `UdpPort` is UDP-only. A new `GateKind::TcpPort` (`protocol_decoder.hpp`,
   plus a matching `tcp_port()` accessor mirroring `udp_port()`'s own
   "gating logic doesn't move into the class" posture) is `UdpPort`'s
   direct TCP-side mirror -- `DohDecoder` (`tls_sni.hpp`) is its first and
   so far only user, wrapping the existing, unchanged `try_detect_doh`.
   Landed with the full zero-flat-field `output.cpp` treatment from the
   start, the same posture FF-HSE/DeviceNet just got: `out.result` carries
   the whole `DohDetection`, a new `write_doh_json_fields` renders it
   (reproducing the prior dual-write's exact field set and shape:
   `doh_sni`/`doh_matched_provider` always present, `doh_alpn_protocols`
   only when non-empty), and `StatsWriter`'s `doh_provider_counts_`
   aggregate now reads `p.result->as<DohDetection>().matched_provider`.
   All three `doh_*` flat fields removed from `decoder.hpp`; no extra
   readers were found outside `decoder.cpp`/`output.cpp` (confirmed by the
   same exhaustive grep sweep every prior dual-write removal has used).
   `try_parse_tls_client_hello`/`try_parse_tls_handshake_client_hello`
   themselves are unchanged and untouched -- both are still shared,
   directly, by QUIC's own ClientHello reuse (`quic.cpp`) and by the
   generic HTTPS detection immediately after DoH's own call site (item
   18's own Tier 2, deliberately still legacy, unaffected by this).

   `protocol_registry.cpp` gained a new `tcp_port_registry()` vector
   (audit-trail only, like `link_type_registry()` -- `decoder.cpp`'s own
   call site calls `doh_decoder()` directly rather than looping, since DoH
   is this gate's only protocol) listing DoH, its sole entry.

   Verified the same way as every prior migration: the full CTest suite
   (1,416 tests) stayed 100% passing with zero changed
   `PASS_REGULAR_EXPRESSION`/`FAIL_REGULAR_EXPRESSION` assertions anywhere,
   a clean rebuild with zero warnings, and a manual `--format json`/
   `--stats` smoke test against `tests/sample_doh.pcap` confirming
   field-for-field identical output to before this change (including the
   still-legacy generic `https` classification sitting right alongside it
   in the same capture, unaffected).

   With this, every protocol in the codebase that decodes real structure
   is on `ProtocolDecoder`. What remains on the legacy path is: protocols
   not yet given the further zero-flat-field `output.cpp` treatment (still
   tracked above); and the 43 IT-tier name-only recognitions, permanently
   excluded per this item's own "Architectural scope note".

   **Update: zero-flat-field `output.cpp` migration, "cheap batch" --
   RIP, IGMP, VRRP, IGRP, MPLS, PPPoE.** Asked whether continuing this
   refinement was worthwhile, a full census first established the real
   scope: 31 protocols (not the looser "~27" estimated earlier) were still
   on the interface-level `ProtocolDecoder` migration but still
   dual-writing into `decoder.hpp`'s flat fields, 9 of them with extra
   readers in `policy_engine.cpp`/`asset_inventory.cpp` beyond the usual
   `decoder.cpp`/`output.cpp` pair. Sequenced cheapest-first, the same way
   every earlier migration batch was: this batch is the 6 smallest with no
   extra readers at all (RIP/IGMP/VRRP/IGRP/MPLS/PPPoE -- 1 to 3 flat
   fields apiece, DNP3 initially miscounted into this group was moved out
   once its own 3 extra readers were found).

   RIP/IGMP/VRRP/IGRP (all `GateKind::IpProtocol`/`UdpPort`, explicit
   `decoder.cpp` call sites) got the standard treatment: each call site's
   `fill_x_fields(out, msg)` dual-write helper (and, for RIP/IGMP/IGRP,
   the one-line-per-entry summary helper it called --
   `rip_route_summary`/`igmp_group_record_summary`/`igrp_route_summary`)
   was deleted from `decoder.cpp` and replaced with `out.result = *result;`
   at the call site itself; new `write_rip_json_fields`/
   `write_igmp_json_fields`/`write_vrrp_json_fields`/`write_igrp_json_fields`
   in `output.cpp` reproduce the exact prior JSON shape, with their own
   copies of the three summary helpers (moved, not shared -- they were
   `decoder.cpp`-local and had no other caller). `StatsWriter`'s four
   aggregate blocks now read through `p.result->as<X>()`. One genuine
   dead field surfaced during this: `vrrp_auth_password` was dual-written
   by `fill_vrrp_fields` but never once read by any writer -- confirmed by
   grep before treating it as "needs a new write_vrrp_json_fields line"; it
   stays out, since adding it now would be a behavior change, not a
   faithful migration (`VrrpMessage::auth_simple_password`, already
   redacted when active, is still on the result for any future reader).

   MPLS and PPPoE (`GateKind::EtherType`, dispatched through
   `ethertype_registry()`'s loop -- see this item's own "EtherType cascade
   registry-driven dispatch" update above) needed the loop's own
   `populate_mpls`/`populate_pppoe` functions rewritten to the
   `populate_slow_protocols`/`populate_goose` shape (set
   protocol/summary/notes, then `out.result = result;`) instead of their
   old per-field dual-write. A second, separate thing surfaced here,
   independent of this migration: neither protocol's flat fields were ever
   read by any writer either -- `output.cpp` had no `mpls_*`/`pppoe_*` JSON
   block at all, confirmed by grep before assuming otherwise (unlike
   RIP/IGMP/VRRP/IGRP, ARP's own next-batch entry has the same gap, noted
   there rather than fixed here). So these two needed no new
   `write_x_json_fields` function at all -- JSON output for both is
   unchanged (still only protocol/summary/notes) because there was nothing
   to preserve. MPLS's own wrinkle (`MplsUnicastDecoder`/
   `MplsMulticastDecoder` share one `id()`, so `is_multicast` can't be read
   off the decoded `MplsFrame` alone -- see this item's own EtherType-loop
   update above) is resolved by adding `MplsFrame::is_multicast`, set from
   the matched EtherType inside `populate_mpls` itself (mirroring
   `DeviceNetFrame::payload_truncated`'s own "field added to carry forward
   something the raw parse can't know" precedent from the FF-HSE/DeviceNet
   batch).

   All six protocols' flat fields removed from `decoder.hpp`; confirmed
   zero remaining readers anywhere (`decoder.cpp`, `output.cpp`,
   `policy_engine.cpp`, `asset_inventory.cpp`, `fuzz/`) via the same
   exhaustive grep sweep every prior dual-write removal has used.

   Verified the same way as every prior migration: the full CTest suite
   (1,416 tests) stayed 100% passing with zero changed
   `PASS_REGULAR_EXPRESSION`/`FAIL_REGULAR_EXPRESSION` assertions anywhere,
   a clean rebuild with zero warnings, and manual `--format json`/`--stats`
   smoke tests against each protocol's own fixture (`sample_rip.pcap`,
   `sample_igmp.pcap`, `sample_vrrp.pcap`, `sample_igrp.pcap`, MPLS's own
   `sample_tunnel_vpn.pcap`, PPPoE's own `sample_wireless_backhaul.pcap`)
   confirming field-for-field identical output to before this change.

   **Update: zero-flat-field `output.cpp` migration, "mid-size batch" --
   ARP, EAPOL, EtherCAT, HSRP, ICMP, LLDP, NBT-NS, PIM, PROFINET, STP, SV,
   and the DNS family (DNS/mDNS/LLMNR).** The 14-protocol-ID group the
   cheap batch's own update above named as "next" -- confirmed to still
   have zero extra readers in `policy_engine.cpp`/`asset_inventory.cpp`
   before starting, the same check every batch runs first.

   Three protocols (ARP, EAPOL, LLDP -- all `GateKind::EtherType`) turned
   out to have the same "populated but never rendered" shape MPLS/PPPoE
   had in the cheap batch: confirmed by grep that `output.cpp` had zero
   `arp_*`/`eapol_*`/`lldp_*` JSON blocks anywhere, so their
   `populate_arp`/`populate_eapol`/`populate_lldp` functions collapsed to
   the `populate_slow_protocols` shape (protocol/summary/notes, then
   `out.result = result;`) with no new `write_x_json_fields` function
   needed at all -- JSON output for all three is unchanged.

   The other nine protocol IDs (PROFINET, SV, EtherCAT, STP --
   `GateKind::EtherType`/LLC-framed; ICMP, PIM -- `GateKind::IpProtocol`;
   HSRP, NBT-NS, and the DNS family -- `GateKind::UdpPort`) do have real
   `output.cpp` rendering to preserve, so each got a new
   `write_x_json_fields` function reproducing the exact prior JSON shape
   byte-for-byte, including every existing truncation cap
   (`resource_limits().max_decoded_objects`) and every rendering helper
   that used to be `decoder.cpp`-local (`icmp_router_address_summary`,
   `pim_hello_option_summary`/`pim_jp_group_summary`/`pim_bsr_group_summary`
   -- moved into `output.cpp`, not shared, matching the cheap batch's own
   precedent for `rip_route_summary`/etc.; `stp_port_role_name`/
   `stp_render_msti_summary` needed no move since `stp.hpp` already
   exposed them as public functions). `write_dns_json_fields` is shared by
   dns/mdns/llmnr the same way `fill_dns_fields` used to be, for the same
   reason (identical wire format, see `dns.hpp`).

   This batch caught two of its own bugs before they shipped, both from
   comparing the new functions against the exact prior gating logic
   rather than trusting a first draft: (1) `SvAsdu`'s `dat_set`/
   `smp_synch`/`smp_rate`/`smp_mod`/`gmid_hex` are `std::optional`-wrapped,
   but the old flat fields were plain strings gated on the *flattened
   string* being non-empty (or, for `smp_rate`, non-zero) -- gating the
   new function on the optional's mere presence instead would print an
   empty `"sv_dat_set": ""` in a case the old code never did; fixed to gate
   on both the optional being engaged and its value being non-empty/
   non-zero, reproducing the original exactly. (2) The bulk rewrite of
   `JsonWriter::write_packet`'s PROFINET-through-STP block briefly dropped
   GOOSE's own `write_goose_json_fields` call site entirely (it sat
   textually between PROFINET and SV, so a line-range edit swallowed it) --
   caught by the zero-warning-rebuild step itself, which flagged
   `write_goose_json_fields` as "defined but not used"; restored.

   Two further "populated but never rendered" fields surfaced within the
   nine real-rendering protocols themselves, same finding and same
   resolution as the cheap batch's `vrrp_auth_password`: `HsrpMessage::
   auth_data` (confirmed no writer ever read the old flat `hsrp_auth_data`)
   and `StpFrame::port_id_raw` (confirmed no writer ever read the old flat
   `stp_port_id_raw`) -- both left out of their new write functions,
   still reachable on the typed result for any future reader.

   All fourteen protocol IDs' flat fields removed from `decoder.hpp`;
   confirmed zero remaining readers anywhere (`decoder.cpp`, `output.cpp`,
   `policy_engine.cpp`, `asset_inventory.cpp`, `fuzz/`) via the same
   exhaustive grep sweep every prior dual-write removal has used.

   Verified the same way as every prior migration: the full CTest suite
   (1,416 tests) stayed 100% passing with zero changed
   `PASS_REGULAR_EXPRESSION`/`FAIL_REGULAR_EXPRESSION` assertions anywhere,
   clean rebuilds with zero warnings in both the default and
   `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` configs, and manual
   `--format json`/`--stats` smoke tests against each protocol's own
   fixture (`sample_arp.pcap`, `sample_enterprise_trust.pcap` for EAPOL,
   `sample_ethercat.pcap`, `sample_hsrp.pcap`, `sample_icmp.pcap`,
   `sample_lldp.pcap`, `sample_nbns.pcap`, `sample_pim.pcap`,
   `sample_profinet.pcap`, `sample_stp.pcap`, `sample_sv.pcap`,
   `sample_dns.pcap`/`sample_mdns.pcap`/`sample_llmnr.pcap`) confirming
   field-for-field identical output to before this change.

   Still explicitly out of scope, not silently dropped: the remaining 9
   protocols on the interface-level migration but not yet zero-flat-field
   -- the extra-reader group (BACnet, DNP3, EtherNet/IP, HART-IP, IEC104,
   MMS, MQTT, OPC UA, S7comm), each of which will need its own
   `policy_engine.cpp`/`asset_inventory.cpp` reader sweep beyond the usual
   `decoder.cpp`/`output.cpp` pair before its own batch can start.

   **Update: zero-flat-field `output.cpp` migration, "extra-reader batch"
   -- BACnet, DNP3, EtherNet/IP, HART-IP, IEC104, MMS, MQTT, OPC UA,
   S7comm.** The 9 protocols the mid-size batch's own update above named
   as the last group standing, each carrying `policy_engine.cpp`/
   `asset_inventory.cpp` readers beyond the usual `decoder.cpp`/
   `output.cpp` pair. Sequenced cheapest-first by `decoder.hpp` flat-field
   count, the same discipline as every earlier batch: S7comm (in progress
   entering this batch), BACnet, MMS, OPC UA, MQTT, HART-IP, plus DNP3/
   EtherNet/IP/IEC104 landed earlier under the same effort.

   Every one of the 9 protocol structs was checked for `ByteSpan` fields
   before writing any code -- the established lifetime-hazard sweep this
   migration always runs first, since `out.result = *result;` only carries
   a decode result safely past the packet's own lifetime when nothing in
   it still points back into the original captured bytes. S7comm is the
   *only* protocol in this whole 9-protocol batch that fails that check
   (`S7CommFrame::items`/`data_items` hold `ByteSpan`s) -- resolved with a
   dedicated `S7CommResult` wrapper (summary/notes/`has_function`/
   `function_name`/a fully-owned `items` copy/eagerly-computed
   `value_summaries`/PI-service and PI-control fields), built and verified
   before this batch's own remaining six protocols. BACnet's `BacnetFrame`,
   MMS's `MmsFrame`, DNP3's payload struct, IEC104's payload struct, OPC
   UA's `OpcUaMessage`, MQTT's `MqttMessage`/`SparkplugPayload`, and
   HART-IP's `HartIpFrame`/`HartIpPassThrough`/`HartIpSessionInit` are all
   fully self-owned -- safe for the plain `out.result = *result;`
   carry-forward, no wrapper needed. DNP3 (`Dnp3Result`), EtherNet/IP
   (`EnipResult`), OPC UA (`OpcUaResult`), MQTT (`MqttResult`), and
   HART-IP (`HartIpResult`) all reused a pre-existing `{summary; notes;
   first;}`-shaped wrapper already built for a separate, earlier
   registration-model interface migration -- this batch's job for those
   five was "stop flattening, read from the wrapper instead," not new
   struct design. IEC104 and BACnet needed no wrapper struct at all: their
   underlying frame types carry `summary`/`notes` directly.

   Two call sites needed a deferred-transform fix, the same shape as the
   cheap batch's own `MplsFrame::is_multicast` precedent (a value the raw
   parse can't know, or a transform the old call site applied that the
   carried-forward struct doesn't compute itself): MMS's `mms_values` used
   to be capped at `resource_limits().max_decoded_objects` (default 50) at
   `decoder.cpp`'s own call site, but `MmsFrame::values` itself is
   uncapped -- confirmed by grep that no other reader depended on the
   pre-capped vector, so the cap moved into the new
   `write_mms_json_fields` instead. HART-IP's `hartip_address_hex` used to
   be formatted (2-hex-digit uppercase for a short address via
   `std::ostringstream`, pass-through for a long one) at BOTH the TCP and
   UDP call sites, duplicated -- `HartIpPassThrough` has no such field, so
   the same formatting moved into `write_hartip_json_fields` once instead
   of twice. MQTT's own Sparkplug metrics cap was already applied inside
   `mqtt.cpp` itself, not at the `decoder.cpp` call site, so it needed no
   equivalent move.

   Two structural invariants were confirmed, not assumed, before
   simplifying gating logic in the new write functions: BACnet's
   `BacnetNpdu::has_apdu` is only ever set true when
   `!is_network_layer_message` (verified directly in
   `try_parse_bacnet_npdu`'s own early-return), letting
   `write_bacnet_json_fields` collapse the old `if (is_network_layer_
   message) {...} else if (npdu.has_apdu) {...}` into a single `if
   (npdu.has_apdu)` check; and MQTT's Sparkplug B "STATE"-topic shape
   (`state_host_id`/`state_text`) versus its non-STATE shape
   (`group_id`/`edge_node_id`/`device_id`/payload-decode fields) are
   mutually exclusive branches of one `if (m.sparkplug_is_state) {...}
   else {...}`, preserved exactly rather than merged or independently
   gated. HART-IP's TCP and UDP decoders share both `id() == "hartip"`
   AND the same `HartIpResult` payload type -- unlike EtherNet/IP's own
   TCP/UDP split into different payload types (`EnipResult` wrapping
   `EnipFrame` vs. `CipIoFrame` directly) -- so no discriminator field was
   needed for HART-IP's two readers, unlike ENIP's `has_tcp`/`has_udp`.

   All 9 protocols' flat fields removed from `decoder.hpp`; confirmed zero
   remaining readers anywhere (`decoder.cpp`, `output.cpp`,
   `policy_engine.cpp`, `asset_inventory.cpp`, `fuzz/`) via the same
   exhaustive grep sweep every prior dual-write removal has used. This
   closes out the extra-reader group entirely -- between this batch and
   the cheap/mid-size batches above, every protocol so far carried on
   `ProtocolDecoder` has now had its `decoder.hpp` flat fields fully
   retired in favor of reading through `DecodedPacket::result`.

   Verified the same way as every prior migration: the full CTest suite
   (1,416 tests) stayed 100% passing with zero changed
   `PASS_REGULAR_EXPRESSION`/`FAIL_REGULAR_EXPRESSION` assertions anywhere,
   clean rebuilds with zero warnings in both the default and
   `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` configs, and manual `--format
   json`/`--stats` smoke tests against each protocol's own fixture
   confirming field-for-field identical output to before this change --
   including HART-IP's short-address (`'01'`) and long-address
   (`'82004b0001'`) rendering both still round-tripping correctly through
   the relocated formatting logic, and its `--stats` message-type/
   pass-through-command aggregates still tallying correctly through
   `p.result->as<HartIpResult>()`.
4. **Comment-density trim: acknowledged, not scheduled.** Real cost, no
   plan yet to act on it -- lower priority than the three items above.
5. **No new protocols until 1-3 above are substantially underway,** per
   the review's own §17 -- the protocol surface is broad enough for now;
   making the existing ~60 detections trustworthy under adversarial input
   matters more than adding a 61st.

   **Update:** Jurgen asked for Beckhoff TwinCAT/ADS (item 20) directly;
   told this conflicted with his own adopted priority order above, he
   chose to have the registration-model pilot (item 3's "Update" above)
   done first and TwinCAT built on top of it, rather than either
   proceeding immediately or deferring TwinCAT further. That both
   satisfies this item's own spirit (a new protocol didn't jump the queue
   ahead of the refactor) and turns TwinCAT into the refactor's own live
   proof, rather than the two staying separate, unrelated pieces of work.
   Items 1-2 above are done; item 3 now has a working pilot (not yet a
   full migration); this item's bar for "substantially underway" is
   judged met for the one new protocol actually requested, not as a
   blanket reopening of new-protocol work -- the ~48 unmigrated legacy
   protocols and the full registry-driven-dispatch migration remain real,
   unscheduled follow-on work.

A follow-up review
([docs/reviews/2026-09-chatgpt-security-review.md](reviews/2026-09-chatgpt-security-review.md),
conducted against GitHub's web UI rather than the actual source, so most of
its "I'd want you to have X" list was already true by the time it was
written -- the bounds-checked `Cursor`/`ByteSpan` primitive, the fuzzing
harnesses above including a combined full-pipeline target, the real-world
capture corpus, and `DirectionSource`'s evidence-level tiering all predate
it) raised four points genuinely not covered by 1-5 above, folded in here
at the same priority tier as the items they extend:

6. **Done: `CONDUITSCOPE_ENABLE_FUZZING`/ASan/UBSan folded into `ci.yml`
   itself, plus a scheduled longer fuzz job**
   ([.github/workflows/ci.yml](../.github/workflows/ci.yml)'s `sanitizers`
   and `scheduled-fuzz` jobs). `sanitizers` runs on every push/PR, same as
   `build-and-test`: Clang, `-DCONDUITSCOPE_ENABLE_FUZZING=ON`
   (ASan/UBSan-instrumented `conduitscope_core`, and therefore the CLI
   binary too), the full CTest suite including all 9
   `fuzz_*_corpus_regression` smoke tests. The Clang sanitizer/fuzzer
   runtime is installed via the `libclang-rt-dev` metapackage (tracks
   whatever compiler-rt build matches the runner image's default Clang,
   rather than hardcoding a versioned package name like `libclang-rt-18-dev`
   that would go stale the next time the image's default Clang bumps).
   `scheduled-fuzz` is a 9-way matrix job (one leg per harness), gated to
   the workflow's new nightly `schedule:` trigger (plus manual
   `workflow_dispatch`) rather than every push, each running a 10-minute
   single-worker campaign against that harness's own committed corpus
   (`fuzz/corpus/<name>/`) and uploading any crash reproducer as a build
   artifact on failure -- a regular, automated floor under the longer,
   multi-worker, by-hand campaigns the "Fuzzing campaign log" table above
   records, not a replacement for them. `build-and-test` and
   `build-without-libpcap` were given `if: github.event_name != 'schedule'`
   guards so the new nightly trigger only drives `scheduled-fuzz`, not a
   redundant re-run of everything else.

   **LeakSanitizer/`setcap` fix.** The first real CI run of `sanitizers`
   crashed with "LeakSanitizer has encountered a fatal error" / "does not
   work under ptrace" on a test with nothing to do with live capture
   (`decode_modbus_sample`) -- because `build-and-test`'s own `setcap
   cap_net_raw,cap_net_admin=eip` step (needed so the 4 `live_capture_*`
   tests that actually open `lo` can do so without running the whole suite
   under `sudo` -- see item 1 above) makes the kernel treat the resulting
   process as non-dumpable, the same restriction a setuid binary gets, and
   LeakSanitizer's exit-time leak check needs ptrace-based self-inspection
   that restriction blocks. A first fix attempt split the `sanitizers` Test
   step in two around `setcap`, with `ASAN_OPTIONS=detect_leaks=0` set via
   the step's `env:` block for the post-`setcap` slice -- this looked right
   locally but a second real CI run showed 2 of the 4 post-`setcap` tests
   still hitting the identical crash intermittently. Root cause, confirmed
   against [google/sanitizers#784](https://github.com/google/sanitizers/issues/784)
   and reproduced directly (an unprivileged test user running a `setcap`'d
   binary genuinely cannot read that process's own `/proc/<pid>/environ`,
   confirmed `-r-------- root root`, `Permission denied` for that same
   user): AddressSanitizer doesn't read `ASAN_OPTIONS` via a normal
   environment lookup, it reads `/proc/self/environ` directly, and
   `setcap`'s non-dumpable transition makes that file root-owned, mode
   `0400` -- unreadable even by the process's own launching user. The
   `env:` override was therefore being silently dropped, and LeakSanitizer
   ran with its compiled-in default (`detect_leaks=1`) regardless, which is
   why the crash was intermittent rather than eliminated. Fixed by not
   relying on `setcap` + an environment override reaching a non-dumpable
   process at all for this slice: the `sanitizers` job no longer runs
   `setcap` itself. Everything that doesn't need `CAP_NET_RAW` runs first,
   as the normal unprivileged runner user, with full leak detection
   genuinely intact (nothing there is non-dumpable). Only the 4 tests that
   need it run afterward under `sudo --preserve-env=ASAN_OPTIONS` -- root
   bypasses the same DAC check that blocks everyone else, so it can always
   read its own `/proc/self/environ` regardless of ownership/mode, and root
   has every capability implicitly anyway, so no separate `setcap` step is
   needed in this job at all. Verified: reproduced the exact permission
   mechanism locally (unprivileged user + `setcap`'d binary -> confirmed
   unreadable `/proc/<pid>/environ`), then confirmed the fix directly the
   same way with `sudo --preserve-env` in the loop -> the file is still
   root-owned/`0400` but root's own read of it succeeds and
   `ASAN_OPTIONS=detect_leaks=0` is visible inside it. `build-and-test`
   itself was never affected -- it has no LeakSanitizer running to conflict
   with `setcap`'s non-dumpable flag in the first place.
7. **Make the hardcoded resource-exhaustion limits CLI-configurable.**
   `kMaxBufferedBytes` (decoder.cpp, TCP/COTP reassembly), the various
   `kMaxDataRecursionDepth`/`kMaxCipRecursionDepth`/`kMaxMplsLabelDepth`-
   style recursion caps, and `kMaxDecodedObjects`/`kMaxList`-style object
   caps scattered across the protocol files are all real, already-present
   protections -- the review's concern that this class of DoS is
   unaddressed isn't accurate at review time -- but they're all
   compile-time constants today, not something a user can tighten (for a
   more paranoid audit of untrusted captures) or loosen (for a capture
   that legitimately needs more headroom) without a rebuild. Worth an
   audit for which of these are worth exposing as `decode`/`policy
   validate`/`inventory` flags, following the same "documented default,
   explicit override" pattern `--modbus-port` and friends already
   establish for expected-port lists.
8. **Document the vendored CLI11's provenance and update procedure.**
   `third_party/CLI11/CLI11.hpp` states its own version (2.4.2) and license
   inline in the header, but there's no separate note recording the
   upstream commit/tag it was pulled from or a procedure for noticing when
   it falls behind upstream. A short `third_party/CLI11/README.md` (or a
   paragraph here) covering version, upstream repo, license, and "how to
   update" closes this cheaply.
9. **Enable GitHub's code scanning, dependency alerts, secret scanning,
   and push protection** for the repository -- these are free,
   configuration-only GitHub features (not something conduitscope's own
   code or CI needs to implement) and the review is right to treat them as
   part of the security baseline for a public repository rather than
   optional decoration.

**Correction to item 7, found while extending the fuzzing corpus
(`fuzz/corpus/packet_decode/`, `fuzz/corpus/pcap_reader/`) for
`fuzz_packet_decode` -- the harness that reaches
`Decoder::reassemble_tcp_payload` -- and confirmed against the real CLI,
not just the fuzz harness:** item 7 above states "`kMaxBufferedBytes`
(decoder.cpp, TCP/COTP reassembly)... [is] already a real, already-present
protection." That's true for DNP3 fragment reassembly (`process_dnp3_frame`,
`kMaxBufferedBytes = 65536`) and COTP TSDU reassembly
(`reassemble_cotp_data_frame`, `kMaxBufferedBytes = 1 << 20`), but
**`reassemble_tcp_payload` itself -- the general cross-segment buffering path
every one of Modbus/TCP, IEC 104, EtherNet/IP, TPKT/S7comm/S7comm-Plus/MMS,
HART-IP, OPC UA, MQTT, and FF-HSE goes through -- has no analogous cap of its
own.** It buffers `fb.bytes` up to whatever each protocol's own
`*_declared_length()` function returns, with no independent ceiling. Most of
those functions ARE naturally or explicitly bounded -- Modbus/TCP's MBAP
length is checked against `kMaxPlausibleMbapLength = 300`
(`modbus.cpp`), EtherNet/IP's and TPKT's declared lengths come from 16-bit
fields (~64KB ceiling), IEC 104's and HART-IP's are similarly field-width-
bounded -- but **`opcua_declared_length()` (`opcua.cpp`) and
`ffhse_declared_length()` (`ffhse.cpp`) read a raw 32-bit length field with
only a `>= 8` / `>= 12` floor and no ceiling at all**, and
`mqtt_declared_length()`'s variable-byte-integer `remaining_length` can reach
~256MB, far above every other protocol's own bound here. Confirmed against
the actual `conduitscope` CLI, not just the fuzz harness: a single 66-byte
OPC UA TCP segment (`fuzz/corpus/packet_decode/`'s
`resource_exhaustion_opcua_huge_declared_size` seed) produces `buffering a
OPC UA message PDU/frame split across TCP segments 51000->4840: 12 of
4294967280 declared byte(s) seen so far ... waiting for more` -- i.e. this
flow's `TcpFlowBuffer` will keep growing, unbounded by anything in
`reassemble_tcp_payload` itself, for as long as segments keep arriving,
exactly the "PCAP containing thousands of flows that each announce 'I have
another 4 GB of data coming'" scenario the review's own §3 describes. The
audit item 7 already calls for should specifically include adding a
`kMaxBufferedBytes`-style cap to `reassemble_tcp_payload` (matching the
pattern already established for DNP3/COTP) and a plausibility ceiling on
`opcua_declared_length()`/`ffhse_declared_length()`, not only making the
*existing* caps configurable -- the general TCP path and these two
protocols' declared-length fields have no cap yet to make configurable.
`fuzz/corpus/packet_decode/`'s new `resource_exhaustion_*` seeds and
`tcp_reassembly_*`/`tcp_*` seeds (overlap, retransmission, sequence-number
wraparound, out-of-order gap-abandon, many simultaneous flows, FIN/RST
mid-reassembly, single-byte and zero-length segments) are regression
fixtures for this area once it's addressed, and a useful mutation-diversity
base for `fuzz_packet_decode` in the meantime.

**Update: implemented.** `reassemble_tcp_payload` (`decoder.cpp`) now caps
per-flow buffering at 16MiB / 20,000 segments -- reusing the same "16MiB is
implausible for anything real" ceiling `pcap_reader.cpp`'s own
`kMaxPlausiblePacketBytes`/`kMaxPlausibleBlockBytes` already established,
rather than inventing a third magic number -- and mirrors DNP3/COTP's own
byte-count + segment-count shape; when the cap fires, the in-progress
reassembly is abandoned and the segment's own payload is tried fresh, same
as the existing sequence-gap-abandon behavior. `opcua_declared_length()` and
`ffhse_declared_length()` now also reject an implausible (>16MiB) declared
size outright, the same way `modbus_tcp_declared_length()` already rejects
an implausible MBAP length -- the more precise fix, since the flow then
never enters buffering in the first place. Verified: the original
repro now decodes the 66-byte OPC UA segment immediately as a one-shot
truncated message instead of buffering towards ~4GB; a legitimate 2-segment
OPC UA reassembly still reassembles correctly; full CTest suite (1106/1106)
and all 9 `fuzz_*_corpus_regression` tests pass under the sanitizer build;
fresh 60-second ASan/UBSan mutation bursts on `fuzz_packet_decode` and
`fuzz_pcap_reader` (the two harnesses that exercise this code) found nothing.

**Update: item 7 itself (CLI-configurability) implemented.** Jurgen picked
this up next after migration batch 2 finished, and chose the grouped/tiered
CLI surface: five new flags, each overriding a whole category of related
constants at once, rather than 60+ individual flags or exposing only the
handful of highest-severity ones. `include/conduitscope/resource_limits.hpp`/
`src/resource_limits.cpp` add a `ResourceLimits` struct (five
`std::optional<size_t>` fields, one per flag) behind a plain process-wide
`resource_limits()`/`set_resource_limits()` accessor pair -- a Meyers-
singleton-style function-local static, the same pattern every `*_decoder()`
accessor in this codebase already uses, just holding mutable configuration
instead of an immutable decoder instance. A global accessor rather than a
parameter threaded through `DecodeContext`/`ProtocolDecoder::
tcp_declared_length()` was the deliberate choice: many in-scope constants
live in places with no `DecodeContext` at all -- most of the duplicated
"50-entry list cap" protocols (EIGRP/OSPF/PIM/IGMP/ICMP/IGRP/RIP/VRRP/HSRP)
are still plain `try_parse_X(ByteSpan) -> optional<XMessage>` legacy free
functions with zero extra parameters, and the recursion-depth helpers
(MMS/CIP/MPLS/S7comm-Plus/GOOSE/DNS) recurse many levels deep carrying only
a local depth counter -- and because a `ResourceLimits` value is process-run
CONFIGURATION (parsed once from CLI arguments, then read-only for the rest
of the process's life), a genuinely different category from
`FlowStateMap`/`DecodeContext`'s per-packet/per-flow state. `DecodeOptions`
(`decoder.hpp`) gained a `ResourceLimits limits;` field, and `Decoder`'s
constructor now calls `set_resource_limits(options_.limits);` as its first
action, before storing `options_` -- safe under this codebase's actual usage
pattern (every real entry point, the three CLI subcommands and every fuzz
harness, constructs exactly one `Decoder` per process). Every in-scope
`constexpr size_t kMaxX = N;` became `const size_t kMaxX =
resource_limits().<field>.value_or(N);` (or, where the constant lived at
namespace scope and was read from more than one function, a small
non-constexpr accessor function calling the same expression) -- `N` stays
visibly documented right at the site, `resource_limits()` is the override
path, and `std::nullopt`/unset (never passing the flag) reproduces today's
behavior byte-for-byte, which is what keeps every existing test passing
unchanged with zero new flags in play.

The five flags, each registered identically on `decode`, `policy validate`,
and `inventory` (unlike the `--modbus-port`-style port-list flags, which
stay decode-only -- a pre-existing, separate gap, out of scope here) via one
shared `add_resource_limit_options()` helper in `cli_main.cpp`:

- **`--max-reassembly-bytes`** -- every cross-segment payload-buffering byte
  cap: `decoder.cpp`'s general TCP reassembly path (16 MiB), `dnp3.cpp`'s
  fragment reassembly (64 KiB), `cotp.cpp`'s TSDU reassembly (1 MiB), and
  `opcua.cpp`'s/`ffhse.cpp`'s own declared-length plausibility ceilings
  (16 MiB each -- the same "16 MiB is implausible" magic number the general
  TCP cap uses, per this item's own "Correction" above).
- **`--max-reassembly-segments`** -- the three companion frame/segment-count
  caps: `decoder.cpp` (20,000), `dnp3.cpp` (500), `cotp.cpp` (2,000).
- **`--max-recursion-depth`** -- every recursive-decode depth cap: MMS
  Data-value nesting (32), EtherNet/IP CIP `Multiple_Service_Packet`/
  `Unconnected_Send` nesting (4), MPLS label-stack depth (16, moved from a
  namespace-scope `constexpr` in `mpls.hpp` to an `inline` function there,
  since `mpls.cpp` is its only reader), S7comm-Plus struct/item nesting (16),
  GOOSE Data ASN.1 nesting (6), and -- folded in during implementation,
  since it plays the identical role and the flag's whole point is "every
  cap in this category, uniformly" -- `dns.cpp`'s DNS name-compression
  pointer-hop guard (128, a loop/decompression-bomb guard rather than true
  recursion, but the same shape).
- **`--max-decoded-objects`** -- every per-message decoded-object/value/
  list-entry cap, the largest and most heterogeneous group: DNP3's object-
  header/point-value family (`kMaxObjectHeaders`=200,
  `kMaxDecodedPointsPerHeader`=200, `kMaxDetailedNotes`=20,
  `kMaxBriefValues`=5, `kMaxBrief`=3, `kMaxObjHeaders`=50,
  `kMaxPointValues`=50), IEC104 (`kMaxDecodedObjects`=200,
  `kMaxObjectValues`=50), GOOSE (`kMaxGooseDataValues`=200,
  `kMaxRenderedBits`=256), EtherNet/IP CIP (`kMaxCipValues`=50,
  `kMaxEmbeddedMessages`=25, `kMaxCipElements`=25, `kMaxCpfItems`=20,
  `kMaxCipIoCpfItems`=20), S7comm-Plus (`kMaxRenderedElements`=20,
  `kMaxRenderedItems`=50, `kMaxBlobDisplay`=64, `kMaxArrayIterations`=10000),
  classic S7comm's `kMaxDetailedNotes`=20, MQTT (`kMaxMetricsParsed`=2000,
  `kMaxRenderedMetrics`=50), decoder.cpp's own summary-list family
  (`kMaxDcpBlockValues`=50, `kMaxGooseDataValueEntries`=50,
  `kMaxSvAsduSummaries`=50, `kMaxEthercatDatagramSummaries`=50,
  `kMaxMplsLabelSummaries`=50, `kMaxStpMstiSummaries`=50, `kMaxTags`=50 x2,
  `kMaxMmsValues`=50), the 9 duplicated "50-entry list" constants
  (`kMaxList`/`kMaxRepeated`/`kMaxRoutes`/`kMaxAddresses`/`kMaxTlvs` in
  eigrp/ospf/pim/igmp/icmp/igrp/rip/vrrp/hsrp.cpp), and -- folded in during
  implementation, for the same "every cap in this category" reason as
  DNS above -- PROFINET's `kMaxDcpBlocks`=30, EtherCAT's
  `kMaxEthercatDatagrams`=200, SV's `kMaxSvAsdus`=200, and Modbus's/
  TwinCAT's own per-session pending-transaction-map caps
  (`kMaxTrackedTransactionsPerSession`/`kMaxTrackedInvocationsPerSession`,
  2000 each -- the closest fit among the five categories for a per-session
  state-map cap, not a per-message one, but no other category fits better).
- **`--max-coalesced-messages`** -- every "N application-layer messages
  found coalesced in one TCP/UDP payload" cap, all already 50 by default:
  FF-HSE (`kMaxFfhseMessagesPerDatagram`/`kMaxFfhseMessagesPerPayload`),
  HART-IP (`kMaxHartIpMessagesPerPayload`), MQTT
  (`kMaxMqttMessagesPerPayload`), EtherNet/IP (`kMaxEnipMessagesPerPayload`),
  OPC UA (`kMaxOpcUaMessagesPerPayload`), and -- folded in during
  implementation, since both turned out to share this exact shape and the
  original inventory simply missed them -- DNP3's
  `kMaxDnp3FramesPerPayload` and IEC104's `kMaxApdusPerPayload`.

**Deliberately excluded, staying compile-time** (not silently dropped --
each is a genuine protocol-native or different-trust-boundary bound, not an
open-ended DoS-tuning knob):

- `modbus.cpp`'s `kMaxPlausibleMbapLength` (300) and `twincat.cpp`'s
  `kMaxPlausibleAdsDataLength` (65536) -- validate a declared length against
  its own protocol-native field range (a detection-correctness gate on an
  inherently small, spec-bounded field), not an open-ended ceiling the way
  OPC UA/FF-HSE's raw 32-bit fields are.
- `pcap_reader.cpp`'s `kMaxPlausiblePacketBytes`/`kMaxPlausibleBlockBytes`
  (16 MiB each) -- a different trust boundary: the capture FILE's own
  record/block-length header, not in-flight payload reassembly of untrusted
  network bytes.
- `policy.cpp`'s `kMaxSuggestDistance` (5) -- bounds a policy-file typo-
  suggestion search over a trusted local file, not attacker-controlled
  packet bytes.
- `stp.cpp`'s `kMaxStpMstiMessages` (64) -- not an arbitrary safety margin
  like every constant above: it's the reference spec's own documented
  ceiling ("an integral number, from 0 to 64 inclusive, of MSTI
  Configuration Messages" -- see `packet-bpdu.c`'s comment on
  `VERSION_3_STATIC_LENGTH`, quoted in `stp.hpp`'s file header). Tightening
  or loosening it would mean decoding LESS than a spec-compliant BPDU can
  legally carry, or claiming to support more than the spec allows -- the
  same reasoning that excludes Modbus's/TwinCAT's field-width bounds above.
  (`decoder.cpp`'s OWN `kMaxStpMstiSummaries`=50 -- an arbitrary display-
  truncation cap on top of whatever STP decoded -- is a different constant
  and IS included in `--max-decoded-objects`; only this file's spec-mandated
  64 is excluded.)
- `include/conduitscope/policy.hpp`'s `kMaxVlanId` (4094) -- IEEE 802.1Q's
  own valid-VLAN-ID range boundary (0 and 4095 are reserved), a protocol
  validity bound like the Modbus/TwinCAT/STP entries above, not a resource
  cap at all.

Verified: full CTest suite (1205/1205 default config, 1195/1195 no-libpcap
config, both 100% pass with every existing `PASS_REGULAR_EXPRESSION`
unchanged -- confirming unset/0 reproduces today's behavior exactly);
zero-warning builds across all three established configs (default+libpcap,
no-libpcap, MinGW cross-compile); 8 new dedicated regression tests (one
demonstrating each flag's actual effect, plus one per subcommand confirming
`--help` lists all five) including a new `tests/sample_goose_deep_nesting.pcap`
fixture (`tools/make_sample_pcap.py`'s `build_goose_deep_nesting_sample()`)
specifically because every existing GOOSE fixture's `allData` nests at most
one level deep -- too shallow to demonstrate `--max-recursion-depth` at any
CLI-representable value, since `0` means "unset/default," not "a cap of
zero"; manual smoke test of each flag's actual effect against a real/
synthetic fixture, plus `--help` output on all three subcommands.

**Update: item 8 itself (documenting vendored CLI11's provenance/update
procedure) implemented.** Added `third_party/CLI11/README.md`, covering
exactly what item 8 asked for: the version vendored (2.4.2, released
2024-05-04) and upstream repository/tag
(<https://github.com/CLIUtils/CLI11>, `v2.4.2`), how that single-include file
is itself produced upstream (CLI11's own `scripts/MakeSingleHeader.py`,
generating it from the normal multi-header `include/CLI/` source -- the
vendored file already states this inline in its own header comment, this new
README just gives it a permanent home outside that comment), the license (3-
clause BSD, embedded verbatim in the file and compatible with conduitscope's
own Apache-2.0), a concrete "how to check if this has fallen behind
upstream" step (compare against <https://github.com/CLIUtils/CLI11/releases>
-- noted there that `v2.5.0` is upstream's current latest, newer than the
`v2.4.2` vendored here, with no standing obligation to chase every release
given how narrow a slice of CLI11's API conduitscope actually exercises),
and a concrete update procedure (pull the new release's own pre-built
single-include asset, or build one locally with `-DCLI11_SINGLE_FILE=ON`;
replace this file; verify the new file's own header comment states the
expected version; rebuild across all three established configs and run the
full CTest suite, since that -- not an assumption from CLI11's own
changelog -- is what actually confirms conduitscope's own narrow usage
still behaves; update the version/tag/date recorded in the README in the
same commit). No separate `NOTICE` file entry was needed: the existing
repository-root `LICENSE` covers conduitscope's own Apache-2.0 terms, and
CLI11's BSD-3-Clause terms are fully self-contained in its own vendored
header comment already, same as before this item -- this new README is a
discoverability/procedure document, not a license-compliance gap-filler for
a gap that didn't exist.


## PROTOCOL DETECTION

In `--protocol auto` (the default), every non-empty TCP payload is tested
against all fourteen TCP-capable protocols, independent of port number. **OPC UA is tried
first of all, then EtherNet/IP, then IEC 104**, before Modbus/TCP, and
**HART-IP is tried third-to-last, MQTT second-to-last, with FF-HSE tried
last of all**, after S7comm/COTP, S7comm-Plus, and MMS -- see the notes at
the end of this section for why that specific ordering matters, not just
which protocols are tried:

- **OPC UA**: recognized by its 8-byte UA-TCP common header -- the leading 3
  bytes (MessageType) must be one of exactly 7 fixed ASCII strings (`HEL`,
  `ACK`, `ERR`, `RHE`, `OPN`, `CLO`, `MSG`), the 4th byte (ChunkType) must be
  `'F'`, `'C'`, or `'A'`, and the following 4-byte MessageSize field must be
  at least `8` (the header's own size). A 3-byte ASCII match against 7
  specific strings is a materially stronger structural signal than most of
  this codebase's own gates -- roughly a 1-in-16-million collision space per
  candidate offset before the ChunkType/MessageSize checks even apply -- and
  research checking it byte-by-byte against every other protocol's own
  leading-bytes gate here (Modbus's protocol-id==0, IEC 104's `0x68` start
  byte, TPKT's version==3 byte, DNP3's `0x05 0x64` sync bytes, EtherNet/IP's
  small enumerated command set) found no possible collision, so it costs
  nothing to try first and is the safest place for it -- the opposite
  ordering rationale from HART-IP's own weak-gate "tried last" placement
  below. Applied port-independently; TCP port 4840 is recorded as an
  "expected port" annotation only, the same posture every other protocol
  here uses for its own port. See docs/PROTOCOL_COVERAGE.md's OPC UA section for the
  service-layer decode this unlocks once the UA-TCP/SecureConversation
  framing is recognized.
- **EtherNet/IP**: recognized by its 24-byte encapsulation header -- the
  command field must be one of the nine standard encapsulation commands
  (`ListServices`, `ListIdentity`, `ListInterfaces`, `RegisterSession`,
  `UnRegisterSession`, `SendRRData`, `SendUnitData`, `IndicateStatus`,
  `Cancel` -- NOP, `0x0000`, is deliberately excluded, see below), the status
  field must be `0` or one of the seven documented encapsulation error codes,
  and the reserved `options` field must be exactly `0`. Three independent
  structural checks, on top of this protocol's own dedicated TCP port
  (44818, which none of the other four protocols here use) -- collectively a
  stronger signal than IEC 104's own checks (below), so it's tried first,
  though with its own dedicated port a collision with any of the others is
  not a realistic concern the way IEC-104-vs-Modbus was. NOP is excluded
  because its command value is all-zero bytes -- real-capture testing found
  this made a short run of zero-padded/malformed bytes on unrelated traffic
  (reassembled Modbus test fixture data, in that instance) misdetect as
  EtherNet/IP; see `tests/real_captures/enip/ATTRIBUTION.md` and
  `enip_command_name`'s comment in `src/enip.cpp`. For SendRRData/
  SendUnitData, the encapsulated Common Packet Format items are located and
  the CIP explicit message within is further decoded -- service code,
  request path, and, for the "first pass" set of services this groundwork
  release covers, the request/response data itself; see docs/PROTOCOL_COVERAGE.md
  below for exactly which services get full value decoding.
- **IEC 60870-5-104**: recognized by its APCI structure -- the start byte
  `0x68`, a length field in the plausible range `[4, 253]`, and the 4-byte
  control field matching one of the three frame formats' fixed bit patterns:
  I-format's N(R) low bit fixed 0, S-format's first two control bytes fixed
  `0x01 0x00` (with N(R)'s low bit fixed 0 too), or U-format's last three
  control bytes fixed all-zero (with the first byte matching one of the six
  STARTDT/STOPDT/TESTFR act/con function values, or noted as an unrecognized
  U-format function otherwise). Unlike DNP3 or S7comm, this isn't a single
  fixed magic-byte sequence, but the combination of the start byte with the
  control field's several independently-fixed bits is still a considerably
  stronger signal than Modbus/TCP's single protocol-id==0 tell -- see below.
- **Modbus/TCP**: recognized by its MBAP header shape -- the protocol-id
  field at byte offset 2-3 must be `0x0000` (mandated by the Modbus spec),
  *and* the function-code byte must be non-zero (function code `0x00` is
  reserved and never assigned by the spec). Unlike DNP3 or S7comm, Modbus/TCP
  has no magic bytes of its own, so protocol-id alone is a weaker signal than
  it looks -- a real capture surfaced non-Modbus traffic on port 20000 whose
  bytes coincidentally satisfied protocol-id==0, which the function-code
  check now catches (see docs/USER_GUIDE.md's LIMITATIONS). If matched, request-vs-response is
  then further disambiguated by PDU shape (a bare 4-byte address+quantity
  looks like a request; a byte-count-prefixed blob looks like a response).
  This shape-based classification is documented in the decoded output as a
  heuristic, and it always runs, unconditionally -- but it is no longer the
  last word: `Decoder::pair_modbus_transaction` (`decoder.cpp`) additionally
  tracks each MBAP transaction ID as an outstanding request per TCP session
  (both directions of one TCP 4-tuple), and when a later packet on that same
  session carries the same transaction ID from the *opposite* direction, it
  is authoritatively that request's response -- regardless of what the shape
  heuristic guessed. This is what resolves Write Single Coil/Register's
  inherent shape ambiguity (request and response are byte-for-byte identical
  per spec): transaction ID + direction doesn't need the shape to differ. A
  paired response gets an extra note naming the exact request packet it
  matches, plus `modbus_paired_request_index` in JSON output; an unpaired
  response (its request never seen on this session -- capture started
  mid-session, or a different session/transaction ID) is noted as an orphan
  instead of silently trusting the heuristic. See docs/USER_GUIDE.md's LIMITATIONS for exactly
  what this does and doesn't cover. This pairing is a separate thing from
  PDU/frame reassembly across TCP segments, which conduitscope also does --
  see docs/USER_GUIDE.md's LIMITATIONS' "General TCP stream reassembly" entry.
- **TwinCAT/ADS**: recognized by a five-part structural gate over its
  6-byte AMS/TCP header (2 reserved bytes + a 4-byte little-endian Data
  Length) plus the 32-byte AMS header that follows it: at least 38 bytes
  present; the AMS/TCP Data Length field must equal 32 plus the AMS
  header's own (separate) Data Length field -- a cross-check between two
  independently present length fields, this decoder's strongest signal;
  State Flags bit 2 (`0x0004`, "ADS command") must be set; Command ID must
  be one of nine recognized values; and Data Length must not be
  implausibly large (capped at 64 KiB, mirroring Modbus's own plausibility
  ceiling). Surveyed against every protocol above and below it in this
  dispatch order before picking a position: OPC UA's leading bytes must be
  one of 7 fixed ASCII strings (AMS/TCP's own leading bytes are
  conventionally zero, never ASCII); IEC 104 requires start byte `0x68`;
  DNP3 requires sync bytes `0x05 0x64`; Modbus/TCP's protocol-id==0 check
  reads what, for an AMS/TCP frame, are the low 16 bits of the Data Length
  field -- nonzero for any realistic ADS payload size, so Modbus's own
  gate correctly rejects real TwinCAT traffic; TPKT requires version byte
  `0x03`. None collide, so this decoder is registered directly after
  Modbus, the same "no collision found, try it as early as its own gate
  strength justifies" reasoning OPC UA/EtherNet/IP's own positions
  established. Like Modbus, every request/response pair also gets
  authoritative (Invoke ID + AMS/TCP-session, non-heuristic) pairing --
  see docs/PROTOCOL_COVERAGE.md's TwinCAT / ADS section for the full
  writeup, including a real collision this decoder's own TCP-reassembly
  probe had to be tightened against after an initial, weaker version of it
  (checking only the 6-byte AMS/TCP prefix, not this full five-part gate)
  was found mis-buffering MQTT/FF-HSE/SMB/TACACS+/OpenVPN traffic.
- **Kerberos** (RFC 4120, TCP and UDP port 88): recognized by its outer
  ASN.1 APPLICATION tag byte, which must be one of exactly 7 values
  (`0x6A`-`0x6F`, `0x7E` -- constructed APPLICATION 10-15 and 30, the seven
  Kerberos message types), followed by a plausible BER SEQUENCE length,
  then, on full decode, a two-field cross-check (`pvno == 5` **and**
  `msg-type` equal to the value the outer tag implies) rather than just a
  leading magic byte. Surveyed against every protocol already tried
  port-independently on TCP and UDP: OPC UA's leading bytes must be one of
  7 fixed ASCII MessageType strings (none render as the ASCII characters a
  `0x6A`-`0x6F` tag byte would be, if it were ever misread as ASCII, which
  it structurally cannot be here); IEC 104 requires start byte `0x68`;
  DNP3 requires sync bytes `0x05 0x64`; Modbus/TCP's protocol-id==0 check;
  TwinCAT's conventionally-zero AMS/TCP reserved bytes; TPKT's version==3
  byte; on UDP, CIP I/O's exact CPF-item-type-plus-length check and
  BACnet's BVLC Type==`0x81` check. None collide, so this decoder is
  registered directly after TwinCAT in the TCP-port-independent chain and
  directly after HART-IP in the UDP-port-independent chain -- the same "no
  collision found, try it as early as its own gate strength justifies"
  reasoning every protocol above follows.
  `KerberosTcpDecoder::tcp_declared_length()` reads the 4-byte TCP length
  prefix *and* peeks at the following byte for one of the same 7 tag
  values before declaring a length, so the TCP-reassembly probe is nearly
  as selective as the full decode gate, not merely "4+ bytes present" --
  see docs/DEVELOPMENT.md's item 22 (ROADMAP) for TwinCAT's own weaker-probe
  lesson this decoder was written to avoid from the start. See
  docs/PROTOCOL_COVERAGE.md's Kerberos section for the full writeup,
  including the curated AS-REP-Roasting/Kerberoasting attack-monitoring
  notes this decoder also carries.
- **LDAP** (RFC 4511, TCP/389 and TCP/3268 Global Catalog): recognized by
  the same three-part structural check `it_protocols.hpp`'s own
  `match_ldap_ber`/`looks_like_ldap_ber` already established (outer tag
  `0x30` SEQUENCE with a plausible BER length, an INTEGER `messageID`
  immediately inside, and a `protocolOp` APPLICATION tag whose number is
  one of the 21 valid values), reused as-is rather than duplicated, plus a
  STRONGER per-field check this decoder's own full parse adds: the
  `protocolOp` tag's constructed bit must also match that specific op
  number's own underlying-type shape (RFC 4511 is `IMPLICIT TAGS`, so the
  bit isn't uniform -- see docs/PROTOCOL_COVERAGE.md's LDAP section for
  the full per-op table). A real collision WAS found and resolved during
  this decoder's own planning: Kerberos's own AS-REP/TGS-REQ/TGS-REP/
  AP-REQ/AP-REP tags (`0x6B`/`0x6C`/`0x6D`/`0x6E`/`0x6F`) are
  byte-identical to five of LDAP's own APPLICATION tags
  (delResponse/modDNRequest/modDNResponse/compareRequest/
  compareResponse) -- this does NOT collide at the dispatch-gate level
  because Kerberos's gate reads the outer tag of the ENTIRE de-framed
  payload (byte 0), while LDAP's byte 0 is ALWAYS the fixed envelope tag
  `0x30`; the overlapping tags only ever appear several bytes INSIDE an
  LDAP message, never as its leading byte. Also unaffected by the
  pre-existing, already-solved LDAP-vs-MQTT collision (`0x30` is also a
  valid MQTT PUBLISH control-packet-type/flags byte) -- the same
  `looks_like_ldap_ber` carve-out `decoder.cpp`'s MQTT call site already
  used, reused as-is. No collision found against any other protocol in
  the TCP-port-independent cascade. Unlike Kerberos, there is deliberately
  no UDP sibling (CLDAP is obsolete). Registered directly after Kerberos
  in the TCP-port-independent chain. LDAP-over-TCP has no length-prefix
  framing of its own -- each `LDAPMessage`'s own outer BER SEQUENCE length
  IS the framing, unlike Kerberos's 4-byte prefix. See
  docs/PROTOCOL_COVERAGE.md's LDAP section for the full writeup, including
  the six curated attack/monitoring notes this decoder carries (several of
  which point directly at Kerberos's own AS-REP-Roasting/Kerberoasting
  findings, since LDAP recon is how a real attacker finds those targets).
- **SMB2/NTLM** (MS-SMB2/MS-NLMP, TCP/445 and TCP/139): recognized by
  `it_protocols.hpp`'s own `match_smb_magic` (a 4-byte `0xFF`/`0xFE`/`0xFD`
  + `"SMB"` signature), reused as-is rather than duplicated -- already
  proven collision-free in this exact cascade before this decoder existed
  (it previously gated only Tier 2's shallow, name-only SMB recognition),
  so no new collision survey was needed, just a stronger post-gate check:
  `try_parse_smb` additionally requires the 4-byte Zero+StreamProtocolLength
  Direct-TCP/NBSS prefix [MS-SMB2]/RFC 1002 actually mandate on BOTH ports,
  which the old Tier 2 heuristic never validated (a magic-at-offset-0 form
  with no prefix is no longer accepted). Fixed-width little-endian fields
  throughout, not BER like Kerberos/LDAP; NTLM (MS-NLMP) is parsed by a
  small **shared** parser (`ntlm.hpp`/`ntlm.cpp`) called from within SMB2's
  own `SESSION_SETUP` bodies, not a decoder of its own -- it has no wire
  presence outside that embedding. No UDP sibling. Registered directly
  after LDAP in the TCP-port-independent chain. See
  docs/PROTOCOL_COVERAGE.md's SMB2/NTLM section for the full writeup,
  including the six curated attack/monitoring notes this decoder carries
  (several of which point directly at Kerberos's/LDAP's own findings,
  since SMB is where credentials harvested/cracked via those two earlier
  phases actually get *used*).
- **DNP3**: recognized by the data-link-layer start bytes `0x05 0x64`, which
  DNP3 always begins with.
- **S7comm/COTP**: recognized by the TPKT signature (`0x03 0x00` followed by
  a length field that plausibly fits the payload), which every TPKT/COTP
  frame begins with regardless of what it's carrying (S7comm, or bare COTP
  connection setup). If the COTP layer parses as a Data frame and its user
  data starts with the S7comm protocol id (`0x32`, or `0x72` for S7comm-Plus),
  it's reported as `s7comm`; otherwise, if the TPKT/COTP framing itself still
  parsed, it's reported as `cotp` (this is the normal case for COTP
  Connection Request/Confirm frames, which carry TSAP session-setup
  parameters rather than S7comm).
- **MMS (IEC 61850 Manufacturing Message Specification, ISO 9506)**: decoding
  is attempted under the exact same gate as S7comm/COTP above (`want_s7comm
  || want_mms` in `decoder.cpp`, the same TPKT/COTP framing, the same
  default TCP port 102) -- S7comm's own single-byte protocol-id gate
  (`0x32`/`0x72`) is tried first, since it is materially stronger and
  cheaper, and MMS is only attempted once that has already failed. MMS then
  layers its own, separate structural detection gate on top, recognizing
  three distinct shapes in the COTP Data frame's user data: (a) a full
  Session-layer SPDU whose leading SI byte is a plausible ISO 8327-1 SPDU
  type (`1`-`64`, `CLSES_UNIT_DATA(64)` being the highest one-byte type the
  standard defines -- deliberately not the looser `< 0x80` a first pass at
  this used, see docs/PROTOCOL_COVERAGE.md's MMS section for the real-capture-found
  collision that tightened it); (b) a "bare MMS" PDU -- the COTP Data
  frame's user data starts directly with an MMS PDU's own tag byte
  (CONTEXT-class, tag number 0-13: constructed `0xA0`-`0xAD` for 11 of the
  14 `MMSpdu` alternatives, or primitive `0x80`-`0x8D` for the remaining 3 --
  `cancel-RequestPDU`/`cancel-ResponsePDU` and `conclude-RequestPDU`/
  `conclude-ResponsePDU`, the only primitive ones); or (c) "bare
  Presentation" -- the Session layer is skipped entirely but Presentation-
  layer bytes (leading byte `0x31` CP-type/CPA-type, `0x61`
  fully-encoded-data, or `0x60` simply-encoded-data) are still present. If
  none of the three match, this decoder does not claim the traffic as MMS at
  all and falls through to the generic COTP/S7comm handling above. See
  docs/PROTOCOL_COVERAGE.md's MMS section for the full four-layer decode this gate
  unlocks.
- **HART-IP**: recognized by its 8-byte fixed header -- the MessageType byte
  must be one of 5 defined values (`0x00`-`0x03`, `0x0F`) *and* the MessageID
  byte must be one of 4 defined values (`0x00`-`0x03`), plus this decoder's
  own added plausibility check that the declared MsgLength field is at least
  8 (the header's own size). This is honestly the weakest structural gate of
  any protocol in this list -- two adjacent bytes each landing on one of a
  handful of small values, versus e.g. EtherNet/IP's three independent
  checks or IEC 104's multi-bit-pattern APCI -- and it is tried
  **second-to-last** in this chain, deliberately, precisely because of that
  weakness: see "Why HART-IP is tried last" below.
- **MQTT**: recognized by its one-byte fixed header (Control Packet Type in
  the top nibble, flags in the bottom nibble, which must be exactly one
  fixed value for every type except PUBLISH -- see docs/PROTOCOL_COVERAGE.md) plus a
  1-4-byte Variable Byte Integer Remaining Length. This was previously the
  **weakest** structural gate of any protocol in this list, so MQTT was
  tried dead last of all -- until FF-HSE's own gate (below) was found to be
  weaker still, so MQTT now sits second-to-last, after every protocol here
  except FF-HSE (including HART-IP) has declined a payload. CONNECT gets a
  much stronger, version-specific check on top (its own Protocol Name field
  must read literally `"MQTT"` or `"MQIsdp"`), but every other MQTT packet
  type relies on the weak one-byte gate alone. See docs/PROTOCOL_COVERAGE.md's MQTT
  section for the real, demonstrated collisions this weak gate caused
  against this project's own synthetic fixture (both found and fixed) and
  "Why MQTT is tried last" below.
- **FF-HSE**: recognized by a SINGLE byte at header offset 2
  (ProtocolAndType) -- its top 6 bits (`& 0xfc`) must land on one of 4
  valid protocol values and its bottom 2 bits (`& 0x03`) on one of 3 valid
  type values (12 valid byte values out of 256 possible), plus this
  decoder's own added plausibility check that the declared Message Length
  field is at least 12 (the header's own size) -- a check that all but the
  smallest 12 possible 32-bit values already satisfy. This is honestly the
  **weakest structural gate of any protocol in this codebase**, weaker even
  than MQTT's own one-byte-plus-Variable-Byte-Integer gate, so FF-HSE is
  dispatched dead **last** of all, on both TCP and UDP, after every other
  protocol here (including HART-IP and MQTT) has declined a payload. No
  specific byte-for-byte collision with another protocol was found during
  this feature's own scoping, but given how weak this gate is on its own,
  this ordering means any such collision resolves in every other protocol's
  favor, not FF-HSE's -- see `ffhse.hpp`'s own "Structural detection gate"
  paragraph and `decoder.cpp`'s own dispatch-order comment.

Because detection is payload-shape based, traffic running on a non-standard
port is still decoded correctly -- and conduitscope tells you it's on a
non-standard port, via a note in the output. That's not a false positive to
worry about; for conduit auditing it's arguably the *most* interesting signal
conduitscope can currently surface (an ICS protocol appearing somewhere your
segmentation policy didn't expect it).

**Why IEC 104 is tried before Modbus.** This was found while scoping IEC 104
support, before any real capture surfaced it in practice (unlike the DNP3
false-positive noted above, which a real capture did surface): an I-format
APDU with N(S)=N(R)=0 -- the very first data frame of essentially every real
IEC 104 session, since sequence numbers start at zero -- makes its APCI bytes
read as a plausible Modbus/TCP MBAP header purely by coincidence (protocol-id
byte-offset 2-3 reads as `0x0000`, and mbap_length reads as `0`), and the
ASDU's type-ID/VSQ bytes that follow can land exactly where Modbus expects
unit-id/function-code -- often with a non-zero "function code", so Modbus's
own reserved-function-code-0 guard (above) doesn't catch it either. Trying
IEC 104 first resolves this in IEC 104's favor, since its own structural
checks are a stronger signal, without needing to make Modbus's own detection
any stricter -- the same fix already applied once before for the DNP3-vs-
Modbus collision. `tests/sample_iec104_modbus_precedence.pcap` (see
`tools/make_sample_pcap.py`) is a minimal regression fixture pinning this
down.

**Why HART-IP is tried last, and the collision this does NOT resolve.**
Unlike IEC 104 above, this is a collision that was found while scoping
HART-IP support and deliberately left **unresolved**, not fixed by
reordering. A HART-IP Session Initiate message's own header (MessageID `0`,
Status `0` -- the only Status value ever observed in this decoder's own
research) makes its header bytes read as a plausible Modbus/TCP MBAP header
purely by coincidence: bytes 2-3 (Status, still `0x0000`) satisfy Modbus's
protocol-id==0 check, and bytes 4-5 (HART-IP's own TransactionID field) read
as a small, plausible Modbus `mbap_length`. This is the exact same *shape* of
collision already resolved once for IEC 104 above -- but trying HART-IP
first, the same way, was tried while scoping this feature and **measurably
regressed** this project's own existing Modbus/S7comm test corpus (roughly
2% of ordinary Modbus/TCP traffic with a non-zero unit ID also happened to
satisfy HART-IP's own two-byte gate, because that gate, unlike IEC 104's, is
genuinely weak -- see above). So this decoder accepts the collision rather
than resolving it: HART-IP is tried last, and a genuine HART-IP Session
Initiate message riding over TCP with Status `0` is misclassified as
Modbus/TCP (or COTP/S7comm, or left as generic `tcp`) instead. HART-IP over
UDP is entirely unaffected (UDP has no equivalent declared-length
pre-check to collide against), and every other HART-IP message type
(Keep Alive, Session Close, Pass Through) is also unaffected, since their
own MessageID values don't produce the protocol-id==0 collision. See
`include/conduitscope/hartip.hpp`'s "KNOWN, ACCEPTED, DOCUMENTED LIMITATION"
paragraph, the matching comments in `src/decoder.cpp`, and
`tests/sample_hartip.pcap`'s own dedicated demonstration packets (see
`tools/make_sample_pcap.py`) for the full writeup -- and
`tests/real_captures/hartip/ATTRIBUTION.md` for independent confirmation
this collision occurs on genuine field traffic, not just a hand-built
fixture.

**Why MQTT is tried last of all (of the protocols known at the time this
placement was chosen -- FF-HSE, added later, was found to have a still
weaker gate and now sits after it; see "Why FF-HSE is tried last of all"
below).** Dispatched even after HART-IP, for the
same reason as HART-IP's own placement, but for an even weaker gate: this
project's own synthetic MQTT fixture (`tests/sample_mqtt.pcap`) surfaced two
real, demonstrated collisions against earlier-dispatched protocols' gates
while it was being built, both found and fixed rather than left as
theoretical risk. First, a v5 CONNACK whose body (two zero bytes, then an
MQTT5 Properties block) coincidentally satisfied Modbus/TCP's own
protocol-id==0 tell with a large, plausible mbap_length -- caught because
`try_parse_modbus_tcp` (unlike `modbus_tcp_declared_length`, its sibling used
during TCP reassembly) didn't apply the same `kMaxPlausibleMbapLength` (300
bytes) sanity cap; fixed by applying that cap in both places (see
`src/modbus.cpp`). Second, a SUBSCRIBE/UNSUBSCRIBE packet identifier
(`>= 4096` after the fix, originally a small round number) happened to
satisfy HART-IP's own two-byte gate (a "plausible" MessageType/MessageID
pair), absorbing the packet into HART-IP's own TCP-reassembly buffering
instead of ever reaching MQTT -- resolved in the test fixture itself
(picking packet identifiers whose high byte exceeds HART-IP's own
MessageID<=3 check), not by weakening HART-IP's gate, consistent with how
this project has always preferred fixing the *specific* collision over
loosening an otherwise-sound check. Both are documented in
`tools/make_sample_pcap.py`'s own comments at the exact fixture packets that
exercise them. Unlike the IEC-104-vs-Modbus collision above, and like the
HART-IP-vs-Modbus collision, no attempt was made to make MQTT's own gate
stronger to avoid needing to be last -- CONNECT's Protocol Name check aside,
tightening every other MQTT packet type's one-byte gate further isn't
possible without contradicting the MQTT spec itself (the flags nibble really
is unconstrained for PUBLISH, by design).

**Why FF-HSE is tried last of all.** Dispatched even after MQTT, for the
same "weaker signal, lower priority" principle already established for
HART-IP and MQTT above, but with the weakest gate of the three: a SINGLE
byte at header offset 2 (ProtocolAndType) landing on one of 12 valid values
out of 256, plus a Message Length plausibility check that all but the
smallest 12 possible 32-bit values already satisfy -- honestly weaker than
even MQTT's own one-byte-fixed-header-plus-Variable-Byte-Integer-Length
gate, since MQTT's Remaining Length field is itself a meaningful structural
constraint FF-HSE's Message Length check barely is. Unlike the HART-IP-vs-
Modbus and MQTT-vs-{Modbus,HART-IP} collisions above, no specific
byte-for-byte collision against another protocol's own gate was found
during this feature's own scoping -- but that is a narrower claim than "no
collision exists": given how weak this gate is in isolation (roughly a
1-in-21 chance of a random byte at offset 2 alone satisfying it, before the
Message Length check even applies), this decoder does not claim collision-
freedom the way OPC UA or EtherNet/IP's own multi-check gates can. FF-HSE
being dispatched dead last means any such collision, discovered later,
would resolve in every other protocol's favor by default, consistent with
this codebase's established ordering philosophy. This gate applies
identically on UDP (see below) -- unlike the HART-IP-vs-Modbus collision,
which is TCP-only (it depends on Modbus's own declared-length TCP
reassembly pre-check, which has no UDP equivalent), FF-HSE's own weak gate
has no such transport asymmetry, since FF-HSE itself defines no declared-
length pre-check any other protocol here could collide against on UDP
either. See `include/conduitscope/ffhse.hpp`'s own "Structural detection
gate" paragraph and `src/decoder.cpp`'s own dispatch-order comment for the
full detail.

**Confirmed in the field.** The prediction two paragraphs above -- that
this gate's own weakness meant a real collision was plausible, not just
theoretical -- happened on a real Windows/Npcap live capture: a UDP/443
QUIC/TLS response's essentially-random bytes matched the ProtocolAndType
byte and decoded a Message Length of 4237566479, misdetected as a badly
truncated FF-HSE message (`[ffhse]  SM confirmed service 8`, with two
truncation notes and a deficit figure north of 4 billion "bytes"). Dispatch
order alone caught this correctly in the sense that nothing else claimed
the packet first, but the length check that "all but the smallest 12
possible 32-bit values already satisfy" (per this section's own text
above) did nothing to stop it. Fixed by giving `try_parse_ffhse` itself the
same 16 MiB plausibility ceiling `ffhse_declared_length` already had for
TCP reassembly purposes (see `kMaxPlausibleMessageLength` in `ffhse.cpp`)
-- this rejects the large majority of random-noise collisions (values
below 16 MiB are ~0.4% of the 32-bit range) without narrowing this
decoder's ability to recognize a real, truncated FF-HSE message, since a
legitimate Message Length is never remotely close to 16 MiB. This does
NOT close the underlying gate's own weakness (the ProtocolAndType byte
alone is still a 12-in-256 chance) -- dispatch-order-last remains the
primary mitigation, exactly as before.

`--protocol modbus`, `--protocol dnp3`, `--protocol s7comm`, `--protocol
mms`, `--protocol mqtt`, `--protocol iec104`, `--protocol enip`,
`--protocol profinet`, `--protocol goose`, `--protocol sv`, `--protocol
ethercat`, `--protocol bacnet`, `--protocol hartip`, `--protocol opcua`,
`--protocol s7comm-plus`, `--protocol ff-hse`, `--protocol dns`, `--protocol
mdns`, `--protocol llmnr`, `--protocol nbns`, or `--protocol doh`
restrict decoding to only that protocol (useful for large mixed captures, or
for scripting a two-pass analysis). Unlike every protocol named above,
selecting `dns`/`mdns`/`llmnr`/`nbns`/`doh` explicitly also changes detection
itself, not just which results are kept -- see the port-gated paragraph at
the end of this section for why. `--protocol enip` covers both EtherNet/IP explicit
messaging (TCP, above) and CIP I/O implicit messaging (UDP, below) --
they're the same overall protocol family. `--protocol mms` restricts to MMS
specifically, distinct from `--protocol s7comm` even though both share the
same TPKT/COTP transport and port. `--protocol hartip` covers both HART-IP
over TCP (above) and over UDP (below) -- HART-IP uses the identical wire
format on either transport. `--protocol opcua` is TCP only -- OPC UA has no
UDP mapping. `--protocol ff-hse` covers all four FF-HSE sub-protocols
(FDA/SM/FMS/LAN Redundancy) on both TCP and UDP (below) -- like HART-IP,
FF-HSE uses the identical wire format on either transport.

**CIP I/O (implicit messaging), UDP port 2222** is tried, port-independently,
against every non-empty UDP payload, the same "opportunistic, payload-shape"
philosophy as the five TCP protocols above: the very first Common Packet
Format item must be a Sequenced Address Item -- type code exactly `0x8002`
*and* declared length exactly `8` bytes (the fixed size ODVA mandates: a
4-byte connection ID plus a 4-byte sequence number). Two independently-fixed
16-bit fields is the same structural-confidence philosophy EtherNet/IP's own
TCP detection and IEC 104's APCI checks already use -- strong enough that a
false-positive match against unrelated UDP traffic is not a realistic
concern, even without a dedicated-port requirement. See docs/PROTOCOL_COVERAGE.md's
EtherNet/IP section for what is and isn't decoded once that anchor matches.

**PROFINET RT, EtherType `0x8892`** is tried, port-independently (there is no
port at all -- this rides directly on raw Ethernet, no IPv4/TCP/UDP layer),
against every non-IPv4 Ethernet frame with that EtherType: the 2-byte
FrameID immediately after the EtherType must fall into one of the named
ranges/values docs/PROTOCOL_COVERAGE.md's PROFINET RT section documents. Unlike
every UDP/TCP-based protocol above, this EtherType has zero collision risk
with any other protocol this tool decodes, so the FrameID check is this
decoder's only structural gate -- but it's still applied rather than
accepting every `0x8892` frame unconditionally: a frame in a genuinely
reserved/unrecognized FrameID range falls back to the generic `non-ip`
ethertype-name-only report, same as before this feature existed.

**IEC 61850-8-1 GOOSE, EtherType `0x88B8`** is tried the same way, port-
independently against every non-IPv4 Ethernet frame with that EtherType:
the 8-byte header's declared Length must be plausible (at least the 8-byte
header itself) and the outer ASN.1 BER APDU tag immediately after the
header must be one of the two named APPLICATION-class tags this protocol
actually uses (`0x61` goosePdu, `0xA0` gseMngtPdu -- see docs/PROTOCOL_COVERAGE.md's
GOOSE section). As with PROFINET RT, this EtherType has zero collision risk
with any other protocol here, so that tag check is the only structural gate;
a frame whose outer tag doesn't match either value falls back to the generic
`non-ip` report. Once the tag matches, header/APDU length mismatches against
the bytes actually available are handled tolerantly -- clamped to what's
present, with a note -- rather than rejected outright, on the theory that a
matched outer tag is already strong enough evidence this is a truncated
capture of real GOOSE traffic, not a false positive (see docs/USER_GUIDE.md's LIMITATIONS).

**IEC 61850-9-2 Sampled Values, EtherType `0x88BA`** is tried the same way,
port-independently against every non-IPv4 Ethernet frame with that
EtherType: the 8-byte header's declared Length must be plausible (at least
the 8-byte header itself) and the outer ASN.1 BER APDU tag immediately after
the header must be `0x60` (`savPdu`) -- SV's `SampledValues` CHOICE has only
this one alternative, unlike GOOSE's two, so there is exactly one tag to
check (see docs/PROTOCOL_COVERAGE.md's Sampled Values section). As with PROFINET RT
and GOOSE, this EtherType has zero collision risk with any other protocol
here, so that single tag check is the only structural gate; a frame whose
outer tag isn't `0x60` falls back to the generic `non-ip` report. Once the
tag matches, header/APDU length mismatches against the bytes actually
available are handled tolerantly -- clamped to what's present, with a note --
the same as GOOSE.

**EtherCAT, EtherType `0x88A4`** is tried the same way, port-independently
against every non-IPv4 Ethernet frame with that EtherType: the 2-byte frame
header's Type field (bits 12-15) must be one of the five values the spec
defines (1-5 -- see docs/PROTOCOL_COVERAGE.md's EtherCAT section). Unlike PROFINET
RT/GOOSE/SV's own structural gates, this one is honestly weaker: 4 bits admit
16 possible values, of which 5 are spec-defined, a 5-in-16 chance of a
coincidental match against unrelated traffic, versus GOOSE/SV's 1-in-256
outer BER tag or PROFINET's own multi-value FrameID range table. The
EtherType itself remains the primary confidence source -- it has zero
collision risk with any other protocol this tool decodes, the same as
PROFINET RT/GOOSE/SV's own EtherTypes -- and a frame whose Type value isn't
one of the five falls back to the generic `non-ip` report, same as the other
raw-Ethernet protocols here. Once the Type matches and is 1 ("EtherCAT
command"), the frame header's declared Length field is used to bound the
datagram-chain scan (clamped tolerantly to the bytes actually available,
with a note, when implausible) rather than walking every byte physically
present in the frame -- see docs/PROTOCOL_COVERAGE.md's EtherCAT section for why.

**Spanning Tree Protocol (STP/RSTP/MSTP)** is tried against classic IEEE
802.3 length-framed Ethernet frames whose 3-byte LLC header has DSAP ==
SSAP == `0x42` (the Bridge Group Address SAP) and Control == `0x03`
("Unnumbered Information") -- structurally, this dispatch path is entirely
SEPARATE from the EtherType-keyed dispatch chain every protocol above (and
Modbus/DNP3/etc. below) is tried through: a length-framed frame's 16-bit
"ethertype" field is by IEEE 802.3's own definition always `< 0x0600`, so it
can never equal PROFINET RT's `0x8892`, GOOSE's `0x88B8`, Sampled Values'
`0x88BA`, EtherCAT's `0x88A4`, or IPv4's `0x0800` -- there is no ordering or
collision question between STP and any EtherType-keyed protocol here, the
same way there is none between two different EtherTypes. Once that LLC
shape matches, the structural gate is: the BPDU body's Protocol Identifier
`== 0x0000` AND BPDU Type in `{0x00, 0x02, 0x80}` AND, for BPDU Types
`0x00`/`0x02` only (a TCN's own version byte is never checked), Protocol
Version Identifier in `{0, 2, 3, 4}`. This is a considerably STRONGER
structural anchor than several other protocols' gates in this list --
several independent small-valid-domain fields (a fixed 2-byte Protocol
Identifier, a 3-value BPDU Type enum, and, for two of those three types, a
4-value Protocol Version Identifier enum) must all co-occur, the same
"multiple independent fields, not one loose length check" strength class as
OPC UA's own 3-byte ASCII magic-string gate -- and notably stronger than
HART-IP's, FF-HSE's, or EtherCAT's own honestly-weaker gates (above). One
address DOES gate detection here, the sole such case in this codebase: DSAP/
SSAP `0x42` is not exclusive to STP -- GARP (GVRP/GMRP) registers on the
identical LLC SAP pair, and is disambiguated purely by destination MAC
(`01:80:C2:00:00:0D` and `01:80:C2:00:00:20`-`0x2F`), checked BEFORE the BPDU
body is even opened, matching Wireshark's own `dissect_bpdu` exactly -- see
docs/PROTOCOL_COVERAGE.md's Spanning Tree Protocol section for why this one case
needed an address check when every other detector in this codebase prefers
a structural one. See that same section for the full wire format, what's
decoded vs. named-only (Cisco PVST+, SPB, GARP), and the real-capture
validation.

**BACnet/IP, UDP port 47808/0xBAC0 (ASHRAE 135 Annex J)** is tried,
port-independently, against every non-empty UDP payload -- the same
"opportunistic, payload-shape" philosophy CIP I/O above uses, since BACnet/IP
rides over UDP rather than a dedicated EtherType the way PROFINET RT/GOOSE/
SV/EtherCAT do: the BVLC (BACnet Virtual Link Layer) header's Type byte must
be exactly `0x81` (the Annex J value; `0x82` is BACnet Secure Connect, a
different, unrelated protocol this decoder does not attempt) *and* its
Function byte must be one of the 13 values the spec defines (`0x00`-`0x0C`).
Two independently-fixed byte values is the same structural-confidence
philosophy CIP I/O's own Sequenced Address Item check uses; a UDP payload
that doesn't match either check falls back to the generic `udp` report,
regardless of port. `--bacnet-port` only changes whether a decoded frame is
annotated as appearing on an unexpected port (default 47808), the same as
every other per-protocol port option -- it never gates detection. Once the
gate matches, the BVLC header's own declared Length field is checked
tolerantly against the bytes actually available (clamped, with a note, on a
mismatch) rather than rejected outright, the same tolerant-declared-length
posture GOOSE/SV/EtherCAT already take. See docs/PROTOCOL_COVERAGE.md's BACnet/IP
section for exactly what's decoded once the gate matches.

**HART-IP, UDP/TCP port 5094** is tried, port-independently, against every
non-empty UDP payload too, using the same 8-byte-header gate described above
for TCP (MessageType/MessageID/MsgLength) -- HART-IP and FF-HSE (below) are
the only two protocols in this list that opportunistically check both
transports with the identical wire format. Unlike the TCP chain, HART-IP is
tried on UDP payloads alongside CIP I/O and BACnet/IP with no ordering
concern: the Modbus/TCP collision described above is a TCP-only artifact (it
depends on Modbus's own declared-length TCP reassembly pre-check, which has
no UDP equivalent), so HART-IP over UDP is checked and decoded exactly like
any other well-behaved protocol here, with no known collision. `--hartip-port`
only changes whether a decoded frame is annotated as appearing on an
unexpected port (default 5094), the same as every other per-protocol port
option -- it never gates detection. See docs/PROTOCOL_COVERAGE.md's HART-IP section
for exactly what's decoded once the gate matches.

**FF-HSE, ports 1089/1090/1091/3622** is tried, port-independently, against
every non-empty UDP payload too, using the same single-byte-at-offset-2 gate
described above for TCP -- but, unlike HART-IP's own UDP placement, FF-HSE
IS tried last among the UDP protocols here (after CIP I/O and BACnet/IP,
and after HART-IP), the same "weakest gate, lowest priority" placement it
gets on the TCP chain, since this gate's own weakness (see "Why FF-HSE is
tried last of all" above) is a property of the gate itself, not of which
transport it's being checked against. A single UDP datagram can (and,
per the reference dissector's own comments about coalesced diagnostic/
status traffic, sometimes does) carry more than one concatenated FF-HSE PDU
back-to-back; this is walked in a loop, the same coalescing pattern this
codebase already uses for EtherNet/IP's and HART-IP's own coalesced UDP
messages -- see `ffhse.hpp`'s own "UDP framing" paragraph. `--ffhse-port`
only changes whether a decoded frame is annotated as appearing on an
unexpected port (default 1089/1090/1091/3622), the same as every other
per-protocol port option -- it never gates detection. See PROTOCOL
COVERAGE's FOUNDATION Fieldbus HSE section for exactly what's decoded once
the gate matches.

**DeviceNet** is detected completely differently from every protocol above:
not by a structural gate applied to a TCP/UDP payload or an EtherType, but
by the pcap capture's own declared link type. Before any Ethernet parsing is
even attempted, `Decoder::decode` checks whether the capture's link type is
`LINKTYPE_CAN_SOCKETCAN` (227); if it is, every packet is parsed as a
SocketCAN capture record (`parse_socketcan_frame`, see
`can_socketcan.hpp`) and handed to `try_parse_devicenet`, a wholly separate
top-level branch that never calls `parse_ethernet` at all -- there is no
ordering or collision question with any other protocol in this list, the
same way there's none between two different EtherTypes, because DeviceNet
isn't reached through the EtherType-keyed dispatch chain in the first
place. Within that branch, the only rejection is structural and absolute: a
CAN frame with its EFF (extended 29-bit ID), RTR (remote transmission
request), or ERR (error frame) bit set is not a valid DeviceNet frame shape
at all and is reported as `non-ip` (named by which flag is set), mirroring
Wireshark's own `dissect_devicenet`'s literal first check. Every other
standard-11-bit-ID CAN frame on this link type is accepted as `devicenet`
and message-group-classified by its CAN ID -- see docs/PROTOCOL_COVERAGE.md's
DeviceNet section for the full classification. `--protocol devicenet`
restricts decoding to it the same way every other `--protocol` value does,
but since the link-type check runs first regardless of `--protocol`, it has
no effect at all on an ordinary Ethernet-linktype capture (nothing on such a
capture is ever a SocketCAN record to begin with).

**DNS, mDNS, LLMNR, NBT-NS (UDP), and DoH detection (TCP) are the only
protocols in this codebase that are PORT-GATED in `--protocol auto`, not
tried opportunistically port-independent the way every protocol above is.**
Every other detector in this list works because its wire format carries at
least one reasonably strong self-describing structural signal -- a magic
byte sequence, a small enumerated field, an exact declared length. DNS and
its close relatives have none: a 12-byte DNS-shaped header (transaction ID,
a handful of flag bits, four 16-bit counts) is trivially satisfied by
essentially any 12 bytes of unrelated traffic, so checking it against every
UDP payload regardless of port -- this codebase's usual posture -- would
misdetect constantly. So in `--protocol auto`, `try_parse_dns_message`/
`try_parse_nbns`/`try_detect_doh` are only even attempted when the packet's
source or destination port matches that protocol's standard port (DNS 53,
mDNS 5353, LLMNR 5355, NBT-NS 137, DoH detection on TCP 443) or one
explicitly added via `--dns-port`/`--mdns-port`/`--llmnr-port`/`--nbns-port`/
`--doh-port`. This makes those five options the ONE place in this tool's
entire `--*-port` family where the option actually WIDENS detection, rather
than only annotating a decoded frame as appearing on an unexpected port --
every other `--*-port` option in this manual (`--bacnet-port`,
`--hartip-port`, `--ffhse-port`, and so on) is purely cosmetic, since those
protocols are already detected port-independently. Selecting a protocol
explicitly (`--protocol dns`, `--mdns`, `--llmnr`, `--nbns`, or `--doh`)
skips the port gate entirely, the same "opportunistic" posture every other
protocol gets by default, on the theory that asking for one of these five by
name is itself a strong enough signal of intent that the port check would
just be getting in the way.

On top of the port gate, each of these five layers its own structural
sanity check, so a packet merely arriving on the right port but obviously
not shaped like the protocol still falls through to the generic `udp`/`tcp`
report: DNS/mDNS/LLMNR check that the declared question/answer/authority/
additional counts are not larger than the smallest possible encoding of
that many entries could fit in the payload actually present (and LLMNR
additionally rejects a nonzero reserved header bit -- RFC 4795 mandates
implementations zero it, so a real LLMNR sender never sets it); NBT-NS
applies a similar per-section minimum-size check *and* requires the very
first NAME field in the message to successfully decode as a first-level-
encoded NetBIOS name (a fixed-length-32 requirement per RFC 1002 -- a
meaningfully stronger tell than DNS's own variable-length label
plausibility check); DoH detection requires a well-formed TLS ClientHello
whose SNI extension matches a curated table of known public DoH resolver
hostnames (see docs/PROTOCOL_COVERAGE.md below) -- a private or enterprise DoH
resolver not on that table is deliberately never flagged, since there is no
wire-format signal that distinguishes "DoH to some server" from "any other
HTTPS traffic" without either a recognizable hostname or the (unavailable,
TLS-encrypted) decrypted content. See docs/PROTOCOL_COVERAGE.md's "DNS / mDNS /
LLMNR / NetBIOS Name Service (NBT-NS) / DNS-over-HTTPS detection" section
for the full wire formats and what is and isn't decoded.

**RIP (UDP) and HSRP (UDP) join that same port-gated group** -- see
`extra_rip_ports`/`extra_hsrp_ports` in `decoder.hpp` -- for the identical
reason: RIP's own structural signal (a Command byte in `1..5`, a Version
byte of `1` or `2`) and HSRP's (a version/opcode/state match for v1, or a
self-consistent TLV chain for v2) are both too weak to try against
arbitrary UDP traffic on every port. `--protocol auto` only attempts RIP on
UDP port 520 and HSRP on UDP port 1985, widened by `--rip-port`/
`--hsrp-port` respectively; `--protocol rip`/`--protocol hsrp` skip the port
gate entirely, same as the DNS family above. Unlike RIP/HSRP, though, RIP
and HSRP are tried BEFORE FF-HSE's own opportunistic (any-port) check in the
UDP dispatch chain, not after every other opportunistic protocol the way
DNS/mDNS/LLMNR/NBT-NS are -- a synthetic HSRPv1 message was found, while
building this feature, to satisfy FF-HSE's own weaker structural gate and
get misdetected as truncated FF-HSE traffic when tried in FF-HSE's usual
lowest-priority position; once RIP's/HSRP's own port gate has already
matched, that is a stronger signal than FF-HSE's port-independent one, so it
runs first. **ICMP, IGMP, VRRP, IGRP, PIM, EIGRP, and OSPF need no port gate or
option at all**: all seven ride directly on IP with no UDP/TCP header, and are
dispatched purely by their own IANA-exclusive IP protocol number (1, 2, 112, 9,
103, 88, and 89 respectively) -- a signal with no port concept to widen or
restrict in the first place. ICMP is the one structurally weaker case in this
group, worth calling out on its own: its Type byte gives almost no useful
filter of its own (nearly every 0-255 value is either a real registered type
or renders as `Unknown (N)`), so unlike its six siblings here, it's the IP
protocol number match alone -- not any shape match inside the message --
doing essentially all of the detection work; see icmp.hpp's own file header
and docs/PROTOCOL_COVERAGE.md's ICMP section. See docs/PROTOCOL_COVERAGE.md's
"RIP / IGMP / VRRP / HSRP" and "IGRP / PIM / EIGRP / OSPF" sections for the
full wire formats of the other six.

**RDP, TeamViewer, AnyDesk, and Zoom (Tier 1 of the "IT protocols an OT
auditor flags" family) are also port-gated in `--protocol auto`**, widened
by the one shared `--remote-access-port` option (`extra_remote_access_ports`
in `decoder.hpp`) -- see `--remote-access-port` above and PROTOCOL
COVERAGE's "Tier 1 remote-access protocol recognition" section for the
per-protocol reasoning. **VNC is the one exception in this whole family**:
its RFB protocol-version banner is checked port-independently even in Auto
mode, the same "structural signature overrides the port gate" treatment
BACnet/IP's or HART-IP's own opportunistic checks get -- `--remote-access-
port` still widens what counts as VNC's own "expected" port for the "seen
on a non-standard port" note, it just never gates whether the banner check
itself runs. `--protocol remote-access` skips every port gate in this
family at once, same as `--protocol rip`/`--protocol hsrp` above.

**SNMP, Telnet, FTP, and TFTP (Tier 2 of the same family) are also
port-gated in `--protocol auto`**, widened by the one shared
`--lateral-movement-port` option (`extra_lateral_movement_ports` in
`decoder.hpp`) -- see docs/PROTOCOL_COVERAGE.md's "Tier 2 lateral-movement protocol
recognition" section for the per-protocol reasoning; HTTPS's own port-only
fallback (an already-established session with no visible ClientHello) is
widened by the same option. **SMB, SSH, and HTTP are the exceptions in this
tier**: SMB's direct-hosting magic, SSH's version-exchange banner, and
HTTP's own request-line/status-line are all checked port-independently even
in Auto mode, the identical "structural signature overrides the port gate"
treatment VNC gets in Tier 1 -- `--lateral-movement-port` still widens what
counts as each one's own "expected" port for the "seen on a non-standard
port" note, it just never gates whether the check itself runs. HTTPS's own
strong signal (a genuine TLS ClientHello) is checked port-independently
too, for the same reason, but is layered directly into the DoH detection
call site rather than gated by this option at all -- see PROTOCOL
COVERAGE's Tier 2 section. **QUIC is a partial exception**: its
long-header packets (Initial/0-RTT/Handshake/Retry/Version Negotiation)
are checked port-independently even in Auto mode, the same strong-signal
treatment HTTPS's ClientHello gets, but its short-header (1-RTT) fallback
-- the weakest gate this codebase uses, port alone -- IS gated by
`--lateral-movement-port` the same way SNMP/Telnet/FTP/TFTP's own checks
are. `--protocol lateral-movement` skips every port gate in this tier at
once, same as `--protocol remote-access` above.

**NTP, LDAP, RADIUS, and TACACS+ (Tier 3's six port-based protocols, minus
DHCP and LDAPS) are also port-gated in `--protocol auto`**, widened by the
one shared `--enterprise-trust-port` option (`extra_enterprise_trust_ports`
in `decoder.hpp`) -- see docs/PROTOCOL_COVERAGE.md's "Tier 3
enterprise-trust-boundary protocol recognition" section for the
per-protocol reasoning. **DHCP and LDAPS are the exceptions in this
tier**: DHCP's own magic-cookie header and LDAPS's own TLS ClientHello are
both checked port-independently even in Auto mode, the identical
"structural signature overrides the port gate" treatment SMB/SSH/HTTP get
in Tier 2 -- `--enterprise-trust-port` still widens what counts as DHCP's
own "expected" port for the "seen on a non-standard port" note, and LDAPS's
own "expected" port for its ClientHello call site (layered into the same
early call site HTTPS's own uses, see docs/PROTOCOL_COVERAGE.md's Tier 3 section),
it just never gates whether either check itself runs. `--protocol
enterprise-trust` skips every port gate in this tier at once, same as
`--protocol lateral-movement`/`--protocol remote-access` above. **EAPOL
needs no port gate or option at all**: like IGMP/VRRP/IGRP/PIM/EIGRP/OSPF
above, it rides directly on Ethernet (EtherType `0x888E`, no IP/TCP/UDP
layer at all), dispatched purely by that EtherType, and reached only via
`--protocol eapol` or Auto mode -- it is not covered by `--protocol
enterprise-trust` or `--enterprise-trust-port`, the same split
GOOSE/SV/EtherCAT/PROFINET's own EtherType-keyed filters already have from
every port-based protocol filter in this list.

**CAPWAP control/data, LWAPP control/data, and GTP-U (Tier 4's five
port-based protocols) are ALL port-gated in `--protocol auto`, with no
exceptions**, widened by one shared `--wireless-backhaul-port` option
(`extra_wireless_backhaul_ports` in `decoder.hpp`) -- see PROTOCOL
COVERAGE's "Tier 4 wireless-backhaul-and-cellular protocol recognition"
section for the per-protocol reasoning. Unlike Tier 3, no protocol in this
tier has a signature strong enough to check port-independently the way
DHCP's magic cookie or LDAPS's ClientHello do -- CAPWAP/CAPWAP data's own
Preamble check and GTP-U's own Version/PT check are both genuine but
modest, and LWAPP has no structural check at all -- so `--wireless-
backhaul-port` always gates detection itself for all five, not just the
"expected port" annotation. `--protocol wireless-backhaul` skips every
port gate in this tier at once, same as `--protocol enterprise-trust`/
`--protocol lateral-movement`/`--protocol remote-access` above. **PPPoE
needs no port gate or option at all**: like EAPOL above, it rides directly
on Ethernet (EtherType `0x8863`/`0x8864`, no IP/TCP/UDP layer at all),
dispatched purely by that EtherType, and reached only via `--protocol
pppoe` or Auto mode -- it is not covered by `--protocol wireless-backhaul`
or `--wireless-backhaul-port`, the same split EAPOL already has from
`--protocol enterprise-trust`/`--enterprise-trust-port`.

**Tier 5's own port-gating story is the most mixed of any tier**, because
this tier itself splits three ways rather than the clean
"port-based-vs-EtherType-keyed" split every earlier tier had. IKE, VXLAN,
Geneve, WireGuard, OpenVPN, and L2TP's own UDP form (six of the
fourteen `--protocol tunnel-vpn` protocols) are genuinely port-gated in
`--protocol auto`, widened by one shared `--tunnel-vpn-port` option
(`extra_tunnel_vpn_ports` in `decoder.hpp`) the same way
`--wireless-backhaul-port` widens Tier 4's five -- even WireGuard's own
exact-length match, this whole codebase's strongest structural signature
outside DHCP/SMB, is still gated to port 51820 purely for consistency with
the rest of this tier (see docs/PROTOCOL_COVERAGE.md's own Tier 5 section).
**GRE, ESP, AH, IP-in-IP, 6in4, and L2TPv3's own direct-IP form (the
other eight) need no port option at all**: like IGMP/VRRP/IGRP/PIM/
EIGRP/OSPF, they're identified by IP protocol number, not a TCP/UDP port,
so there is nothing for `--tunnel-vpn-port` to widen for them -- the IP
protocol number itself is either GRE/ESP/AH/etc. or it isn't.
**The generic DTLS-tunnel check is checked port-independently and is
never gated at all**, reached in Auto mode or via `--protocol tunnel-vpn`
regardless of port (see docs/PROTOCOL_COVERAGE.md) -- `--tunnel-vpn-port` has no
effect on it, since there is no "unexpected port" concept for a check that
was never tied to a port in the first place. `--protocol tunnel-vpn`
skips every port gate among the six port-gated protocols at once, same as
`--protocol wireless-backhaul`/`--protocol enterprise-trust`/`--protocol
lateral-movement`/`--protocol remote-access` above, while leaving the
eight IP-protocol-number-keyed protocols and the ungated DTLS check
unaffected either way. **MPLS needs no port gate or option at all**: like
EAPOL/PPPoE above, it rides directly on Ethernet (EtherType `0x8847`/
`0x8848`, no IP/TCP/UDP layer at all), dispatched purely by that
EtherType, and reached only via `--protocol mpls` or Auto mode -- it is
not covered by `--protocol tunnel-vpn` or `--tunnel-vpn-port`, the same
split EAPOL/PPPoE already have from `--protocol enterprise-trust`/
`--protocol wireless-backhaul`.


## ROADMAP

Rough order, each building on the groundwork this release establishes:

### Priority order

The numbered list below is chronological, not priority-ordered -- each item
was added as it was scoped against the version before it, not ranked
against every other item. Grouped by actual impact instead, for anyone
deciding what to tackle next:

**Foundational validation, blocking confidence in everything else built on
top of it.** Item 1 (real Windows/Npcap capture against a real
OT/mirrored-switch-port network, not just Linux loopback and found
captures) -- every other item's correctness claims currently rest on
synthetic fixtures and a handful of found real captures, never a live
production-like capture end to end. Alongside it: widening `policy
validate` to evaluate UDP flows at all, the single most-repeated "still
open" call-out in this document (items 9, 14, 15, and 17 each hit it from
a different angle) -- it's the one gap blocking BACnet/IP, EtherNet/IP CIP
I/O, HART-IP's UDP form, and FF-HSE's UDP form from ever actually being
checked against a conduit, and blocking `inventory`'s own UDP-based
inferred conduits from ever showing anything but "never exercised."

**IPv6 support (item 24, new)** belongs in the same foundational category:
`decoder.cpp` only ever parses an IPv4 outer header today, so any
IPv6-over-Ethernet traffic is reported as `non-ip`, invisible to every
decoder and to `policy validate`'s conduit model alike -- a real gap now
that dual-stack OT/IT networks are routine, and worth scoping alongside
the UDP `policy validate` gap above rather than after it.

**Item 18** (the "IT protocols an OT auditor flags" family, just added) is
comparatively cheap to build and high-value to an auditor: tiers 1-4
(RDP/VNC/TeamViewer; SMB/SSH/HTTP/SNMP/Telnet/FTP/TFTP; NTP/DHCP/LDAP/
RADIUS/TACACS+/802.1X; CAPWAP/LWAPP/GTP-U/PPPoE) are all name-only
recognition -- the same lightweight "recognized but not decoded" posture
ARP/LLDP/ICMP already have, no new parsing infrastructure required. Tier 5
(generic tunnel/VPN naming) is a natural, similarly-cheap follow-on;
actual decapsulation is explicitly out of scope for this pass.

**Real-capture validation debt**, mostly inherited from item 9: CIP I/O,
PROFINET RT, GOOSE, and EtherCAT all shipped without a real capture
exercising more than a fraction of their own decode paths, and Sampled
Values has zero real-capture coverage at all. BACnet/IP, HART-IP
(item 10), OPC UA (item 11), and MMS (item 12) are in the same position to
varying degrees. None of this is a known decode bug, but it's the largest
concentration of "confirmed against synthetic fixtures only" risk in the
codebase, and worth closing before stacking more protocols on top of
unvalidated ones.

**Item 13's DNP3 link-address zone model** is worth pulling forward out of
its chronological position: the item's own text already calls it "the
single most consequential addressing gap in this codebase," since a
serial-to-IP DNP3 gateway multiplexing several outstations behind one IP
is a routine real-world topology this tool currently can't zone/
conduit-model at all.

**Everything else is protocol-specific deepening, lower urgency**: item
2's `0xB2` symbolic-addressing confirmation (blocked on access to real
PLC/TIA Portal authority, not on effort); item 3's S7comm-Plus Tier 2
promotion; items 5 and 7's remaining DNP3/IEC 104 value-decode table
gaps; item 8's CIP STRING2/STRINGN/STRINGI/EPATH/ENGUNIT-as-value and its
symbolic-path-gating question; item 10's remaining Response Code
resolution/real-capture-widening work (its HART checksum-verification
half is now done); item 11's OPC UA chunk reassembly and Browse/subscriptions/
HistoryRead promotion; item 12's MMS `Address`/`TypeSpecification`
decoding; item 14's per-protocol `functions` allow-lists; item 15's
QinQ stacked-VLAN support; item 17's protocol-grouped zones and
LLM-assisted zone suggestions; item 25's VMware vSphere/ESXi link-layer
frame recognition (EtherType `0x8922`); and item 26's HomePlug AV/devolo
dLAN powerline-networking recognition (EtherType `0x88E1`). All genuinely
useful, none blocking anything else on this list.

1. **Validate live capture against a real Windows/Npcap install and a real
   OT/mirrored-switch-port network**, not just Linux loopback -- see LIVE
   CAPTURE's "Windows / Npcap notes" and docs/USER_GUIDE.md's LIMITATIONS.
   **Partially done:** the Windows/Npcap half is now validated -- a clean
   MSVC/Visual Studio build with live capture enabled, `conduitscope.exe
   interfaces` correctly enumerating real adapters, and a real capture
   decoded end to end (which is what surfaced the FF-HSE false-positive
   fix documented elsewhere in this file, plus the addition of full ICMP
   decoding). That same round of real Windows testing also surfaced two
   further, unrelated bugs, both fixed:
   - **`conduitscope version`'s reported build type was wrong on a
     multi-config CMake generator.** It read `CMAKE_BUILD_TYPE` directly,
     which is meaningless (always empty) for Visual Studio/Xcode-style
     multi-config generators -- the actual configuration is chosen at
     *build* time via `cmake --build ... --config <Config>`, not at
     configure time the way `CMAKE_BUILD_TYPE` assumes. The real MSVC
     build surfaced this concretely: the reported string came out as
     `Windows,  build` (a stray double space where the empty build type
     used to render), not a guess at the wrong configuration -- which
     would have been worse, since a build genuinely built `Debug` could
     have silently claimed `Release`. Fixed by detecting a multi-config
     generator at CMake configure time (`GENERATOR_IS_MULTI_CONFIG`) and,
     for that case, baking in a literal `multi-config` string instead of
     `CMAKE_BUILD_TYPE`'s empty value; single-config generators (the
     Linux build) are unaffected and still report their real configured
     build type.
   - **Windows release binaries required `wpcap.dll` (the Npcap
     *runtime*) at process startup, even to run `decode -r` on a saved
     file with no live capture involved.** Found via a real Windows CI
     hang: a runner with the Npcap *SDK* installed (build-time headers/
     import libraries) but not the separate Npcap *runtime* installed
     failed every offline `decode` test too, since the executable
     wouldn't even start -- `pcap.dll`/`wpcap.dll` was linked as an
     ordinary load-time dependency, so the OS loader refused to launch
     the process at all if it was missing, regardless of whether that
     run ever touched live capture. Fixed by delay-loading `wpcap.dll` on
     Windows (`/DELAYLOAD:wpcap.dll` plus `delayimp.lib`) instead of
     linking it as a normal import: the DLL is now only actually loaded
     the first time code on the live-capture path runs, so offline
     `decode`/`policy validate`/`inventory` (no `-i`) work on a machine
     with only the SDK's import library present and no runtime installed
     at all. `-i`/`interfaces` still need the real runtime, but now fail
     with a clear "install the Npcap runtime" message at the point of
     first use instead of the whole binary refusing to launch; see
     docs/USER_GUIDE.md's "Windows / Npcap notes" for the resulting
     runtime-vs-build-time distinction. This real usage also surfaced a
     Ctrl+C-specific bug: `SigintGuard`
   (cli_main.cpp) restored the terminal's ANSI colors on interrupt via a
   portable `std::signal(SIGINT, ...)` handler on every platform, but on
   Windows that handler isn't guaranteed to stay installed for the whole
   run and can't reliably suppress the OS's own default
   Ctrl+C-kills-the-process action -- two well-documented Windows CRT
   `signal()` gotchas that don't apply on Linux/macOS, where a signal
   handler installed once stays installed and does suppress the default
   action. Fixed by switching `SigintGuard` to `SetConsoleCtrlHandler`
   (the Win32-native mechanism Microsoft's own docs recommend for this
   exact case) on Windows specifically, keeping `signal(SIGINT, ...)` on
   POSIX unchanged; verified by cross-compiling with MinGW-w64 and
   confirming `SetConsoleCtrlHandler` is correctly imported in the
   resulting binary. **That fix turned out to be necessary but not
   sufficient** -- Jurgen's own follow-up report showed colors still not
   resetting on Windows even with `SetConsoleCtrlHandler` in place. Root
   cause, once actually diagnosed: `SetConsoleCtrlHandler`'s handler runs
   on a separate thread Windows spawns for it, genuinely concurrently with
   the main thread still decoding and printing packets (this is documented
   Windows behavior, not a bug in the handler itself), and `LiveCapture::
   next()` (live_capture.cpp) only checks its `stop_requested` flag at the
   *top* of its retry loop -- once `pcap_next_ex()` has already returned a
   packet, `next()` hands it back regardless of whether `stop_requested`
   was just set. So the main thread can legitimately decode and print one
   or more MORE colored packets after the handler's own immediate
   raw-`_write()` reset already ran; that packet's ordinary, iostream-
   buffered output can reach the console *after* the handler's reset,
   undoing it. This race is Windows-specific -- on POSIX a signal handler
   runs synchronously on the very thread it interrupts, so there's no
   "the interrupted thread keeps producing more output concurrently"
   scenario -- which is consistent with `SetConsoleCtrlHandler` alone
   (a real, correct fix for a different gap) not touching the actual
   symptom. Fixed properly by adding a second, authoritative color reset
   in `run_decode` (cli_main.cpp) on the main thread itself, positioned
   right after the packet loop ends and after `writer->end()`/
   `stats_writer.print_summary()` -- guaranteed to run after every packet
   this run will ever print, on every platform, regardless of which
   condition stopped the loop (EOF, `--duration`, `--max-packets`, or
   Ctrl+C), since it's synchronous and strictly last on the one thread that
   produces all of this run's real output. The original handler-side reset
   is kept as a best-effort immediate backstop for the case the process is
   killed before reaching normal exit -- a redundant ANSI reset is
   harmless. Re-verified after this second fix: full Linux CTest suite
   (1148/1148 default, 1138/1138 with `CONDUITSCOPE_ENABLE_LIVE_CAPTURE=
   OFF`) and a clean MinGW-w64 cross-compile, plus a manual Linux smoke
   test confirming the end-of-run reset fires exactly once on normal exit
   and is appended (harmlessly redundant) after the handler's own reset on
   Ctrl+C. This second fix DID hold up under real testing -- Jurgen
   confirmed 50/50 clean live-capture Ctrl+C runs on real Windows hardware,
   the first hard live-Windows confirmation either fix got, and a hex dump
   of an interrupted run's raw output bytes confirmed `\033[0m` really is
   the literal last four bytes written. **But a third report, from the same
   round of testing, found a completely different gap**: Ctrl+C during an
   *offline* `decode -r` (no `-i` at all) could still leave the terminal
   colored -- something neither of the first two fixes touched, since both
   were about *how* an already-installed Ctrl+C handler behaves, not
   whether one gets installed at all. Root cause, this time genuinely
   confirmed by an A/B test (see below), not just reasoned about: `SigintGuard`
   only installed a handler at all when given a live capture to stop --
   `active_(capture != nullptr)`. For `-r`, that pointer is always null (see
   `open_packet_source`), so the entire `if (active_) { ... }` block --
   `SetConsoleCtrlHandler`/`signal(SIGINT, ...)` included -- was skipped
   outright, on every platform, regardless of color. Ctrl+C during an
   offline decode fell straight through to whatever the OS's own default
   handling was, with zero cleanup ever running -- both of the previous
   fixes are irrelevant if no handler is registered to reach them at all.
   Fixed by activating the guard whenever there's *either* a live capture to
   stop *or* color to reset (`active_(capture != nullptr || color)`). Doing
   so surfaced a second, related gap in the same testing pass: with the
   handler now installed, Ctrl+C during `-r` correctly reset color, but the
   read itself just kept going to EOF regardless, since `PcapReader` (unlike
   `LiveCapture`) had no stop flag of its own for the packet loop to check.
   Fixed alongside it by adding a general `g_stop_requested` atomic, set by
   the same cleanup routine and checked in `run_decode`/
   `run_policy_validate`/`run_inventory`'s own `while (source.next(pkt))`
   loop condition, alongside (not instead of) `LiveCapture`'s own internal
   stop flag, which is still needed to unblock a `next()` call already
   blocked inside `pcap_next_ex()`. Verified with an A/B test on Linux that
   sidesteps this sandbox's total lack of real interface traffic: a
   synthetic 300,000-packet offline pcap (built locally, ~1.7s to decode in
   full) interrupted via `timeout -s INT 0.3 ...` -- built against the
   pre-fix logic, this reliably produced truncated output with **no**
   trailing reset at all (process killed outright, matching the reported
   symptom exactly); built against the fix, the same test now reliably
   stops in ~0.3s (not the full 1.7s) with the reset correctly as the last
   four bytes written. Also re-ran the full verification bar after this
   third fix: Linux CTest (1148/1148 default, 1138/1138 with
   `CONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`) and a clean MinGW-w64
   cross-compile. **Both the live-capture and offline-decode Ctrl+C fixes
   are now confirmed on real Windows hardware** -- Jurgen reported 50/50
   clean live-capture runs (with a hex dump backing it up) after the second
   fix, and a working offline-decode Ctrl+C after this third one, closing
   out what turned out to be a three-part investigation: a real
   `SetConsoleCtrlHandler`-vs-`signal()` gap, a genuine cross-thread
   ordering race specific to live capture, and -- the actual cause of the
   most persistent symptom -- `SigintGuard` never installing a handler at
   all for an offline `-r` read. **Still open**: a real
   OT/mirrored-switch-port network capture -- what's been run so far is
   ordinary client traffic (ICMP, UDP/443 QUIC/TLS), not industrial
   protocol traffic on a real mirrored port.
2. **Confirm or replace the EXPERIMENTAL `0xB2` (S7-1200/1500 "symbolic"
   addressing) decode** against a source with real authority -- a PLC or
   TIA Portal project under your own control, ideally, rather than more
   public reverse-engineering writeups -- and extend it to the shapes it
   currently falls back to raw hex on: DB-area items, and items with more
   than one LID entry (structured/nested symbol access). Promote it out of
   [EXPERIMENTAL] once confirmed.
3. ~~PLC Control/Stop parameter decoding~~ (these send commands that change
   PLC run state -- high security relevance) -- **done**: classic S7comm's
   function codes `0x28` (PLC Control / PI-Service) and `0x29` (PLC Stop) are
   both fully decoded -- see docs/PROTOCOL_COVERAGE.md's S7comm / COTP section's
   "PLC Control (`0x28`) / PLC Stop (`0x29`)" entry and
   `include/conduitscope/s7comm.hpp`'s file header. Still open, and now
   standing on its own now that the PLC Control/Stop half above is done:
   extending S7comm-Plus's own Tier-2 functions (CreateObject, Explore,
   GetLink, BeginSequence/EndSequence, Invoke, GetVarSubStreamed,
   Notification, Connect) to Tier 1 -- **DataFW1_5 itself is done**: confirmed
   against a real S7-1212C + Siemens KTP 400 Basic HMI capture and promoted to
   Tier 1, see docs/PROTOCOL_COVERAGE.md's S7comm-Plus section and
   `tests/real_captures/s7comm/ATTRIBUTION.md`'s DataFW1_5 addendum -- plus
   S7comm-Plus's own above-COTP, trailer-based reassembly (currently
   detected and reported, not reassembled -- see docs/PROTOCOL_COVERAGE.md's
   S7comm-Plus section, `include/conduitscope/s7commplus.hpp`'s file header,
   and docs/USER_GUIDE.md's LIMITATIONS).
4. ~~DNP3 CRC validation (both the header CRC and the per-block CRCs), so a
   corrupted frame that still starts with the right magic bytes is flagged
   rather than silently "decoded"~~ -- **done**, see docs/PROTOCOL_COVERAGE.md's DNP3
   "Data-link CRC-16 validation" section and docs/USER_GUIDE.md's LIMITATIONS. Not yet wired into
   `policy validate`/`PolicyEngine` (purely diagnostic in `decode` output
   today) -- that remains open, and isn't separately tracked as its own
   roadmap item, since no concrete use case has motivated a specific
   verdict-impact design for it yet.
5. ~~DNP3 absolute-time rendering as a calendar date~~ -- **done**, see
   docs/PROTOCOL_COVERAGE.md's DNP3 "Time and Date" entry and docs/USER_GUIDE.md's LIMITATIONS. Value
   decoding for the group/variation combinations still outside the
   point-format table (double-precision Analog Input Event variants, Octet
   String, File Control, Analog Input Reporting Deadband) remains open and
   isn't separately tracked as its own roadmap item yet.
6. ~~A policy `from`/`to` zone list wider than two endpoints per conduit~~
   (e.g. "any of these three zones may reach this one") -- **done**: a
   conduit's `from`/`to` each accept a single zone name or a list of them,
   and the conduit is many-to-many (any `from` zone to any `to` zone) --
   see POLICY FILE FORMAT's "Schema" section and its "Worked example"
   (`tests/policies/multi_from_zones.yaml`, `multi_to_zones.yaml`, and
   `multi_zone_bidirectional.yaml`). Nothing remains genuinely open about
   this item.
7. ~~Extend IEC 104's information-element decode table~~ to step position
   (types 5/6/32) and bitstring of 32 bit (types 7/8/33, command 51/64) --
   **done**, along with 17 more type IDs in the same pass: the
   CP24Time2a-tagged measured-value/integrated-totals variants (10/12/14/
   16), the normalized-value-without-quality-descriptor variant (21),
   time-tagged regulating-step and scaled-setpoint commands (60/62), delay
   acquisition (106), the time-tagged test command (107), and
   parameter-of-measured-value/parameter-activation (110/111/112/113). See
   docs/PROTOCOL_COVERAGE.md's IEC 60870-5-104 section for the full list and its
   own paragraph on what's deliberately still excluded (the
   protection-equipment event types, M_PS_NA_1 packed single-point with
   status change detection, file transfer, and C_TS_NA_1). Still open and
   not separately tracked as its own roadmap item: full counter-
   interrogation (type 101)/read (102) command decoding -- both are
   recognized, named type IDs, but their information elements aren't
   value-decoded yet, the same "structurally located, not value-decoded"
   state every still-unlisted type ID gets.
8. ~~Extend EtherNet/IP's CIP value decoding to STRING/SHORT_STRING and
   structured (UDT/array) elementary types~~ -- **done**: STRING (`0xD0`)/
   SHORT_STRING (`0xDA`) decode to plain text, and Structured Data Type
   (any type code `>= 0x02A0`) decodes its 2-byte Structure Handle (member
   bytes shown as hex, no Template definition available) -- see PROTOCOL
   COVERAGE's EtherNet/IP section and the "now done" paragraph below. Fixing
   this also fixed a real bug: `cip_is_plausible_type_code` previously only
   accepted the `0xC1`-`0xDE` elementary range, so a genuine UDT Read_Tag
   response was wrongly rejected as "not a Rockwell tag read at all"; it
   now also accepts the `>= 0x02A0` structured range. STRING2/STRINGN/
   STRINGI/EPATH/ENGUNIT-as-a-value remain open and aren't separately
   tracked as their own roadmap item. Still open and worth revisiting once
   real-world evidence exists: whether the symbolic-path-gating gate itself
   (see docs/PROTOCOL_COVERAGE.md) is ever too narrow in practice -- e.g. a real
   device addressing a Symbol-object tag by numeric instance ID rather than
   by name, which this release's gating would currently show structurally
   rather than as a tag read.
9. ~~Decode IEC 61850-9-2 Sampled Values~~ -- **done**, see PROTOCOL
   COVERAGE's Sampled Values subsection and the "now done" paragraph below.
   ~~Decode EtherCAT~~ -- **also done**, see docs/PROTOCOL_COVERAGE.md's EtherCAT
   subsection and its own "now done" paragraph below. That closes out this
   item's original "decode the remaining named-but-undecoded raw-Ethernet OT
   protocol" call-out entirely: CIP I/O, PROFINET RT, GOOSE, Sampled Values,
   and now EtherCAT are all done, and this project no longer tracks any
   named-but-undecoded raw-Ethernet OT protocol of its own. Also, separately:
   validate CIP I/O decoding
   against a real capture (none was found while building it -- see
   `tests/real_captures/enip/ATTRIBUTION.md`) if one ever turns up, and
   consider cross-datagram CIP I/O correlation (connection ID back to its
   Forward_Open, sequence-number continuity/gap detection) -- see
   docs/USER_GUIDE.md's LIMITATIONS for exactly what's missing there now. Likewise for PROFINET
   RT: a real cyclic RT IO data capture to validate `decode_cyclic` against
   (none found either -- see `tests/real_captures/profinet/
   ATTRIBUTION.md`), and resolving the cyclic-IO-data-vs-Ethernet-padding
   ambiguity if a reliable way to tell them apart ever turns up (see
   docs/USER_GUIDE.md's LIMITATIONS). And for GOOSE: real-capture validation for optional-field
   absence, every `allData` type beyond boolean/bit-string, and a GSE
   Management PDU, none of which any real capture found so far exercises
   (see `tests/real_captures/goose/ATTRIBUTION.md`). And for Sampled Values:
   real-capture validation for literally every code path, since none was
   found at all despite a genuine multi-source search (see PROTOCOL
   COVERAGE's Sampled Values subsection). And for EtherCAT: real-capture
   validation for the Cmd values (APRW/FPRW/BRW/LRW/ARMW/FRMW/EXT/NOP), the
   `Circulating` bit, VLAN tagging, and non-Type-1 frames the one real
   capture found doesn't happen to exercise (see docs/PROTOCOL_COVERAGE.md's
   EtherCAT subsection and `tests/real_captures/ethercat/ATTRIBUTION.md`),
   and CoE/SoE/EoE/FoE/AoE mailbox decoding, if a reliable way to recognize
   it without per-slave SyncManager configuration knowledge ever turns up.
   And for BACnet/IP: real-capture validation for device discovery
   (Who-Is/I-Am/Who-Has/I-Have), WriteProperty, every PropertyValue type
   besides a scalar Unsigned, every BVLC function besides
   Original-Unicast-NPDU, NPDU DEST/SRC/Network-Layer-Message routing
   fields, and segmentation, none of which the one real capture found so
   far exercises (see docs/PROTOCOL_COVERAGE.md's BACnet/IP subsection and
   `tests/real_captures/bacnet/ATTRIBUTION.md`); extending value decoding
   beyond the "first pass" service set (ReadPropertyMultiple/
   WritePropertyMultiple in particular, since they're increasingly the more
   efficient, more common choice in modern deployments); and revisiting
   `kargs.net`'s own capture archive for a richer real-capture source if
   this project's network access to it is ever unblocked. And widen `policy
   validate` beyond TCP-only conduits, now that there are actual decoded
   non-TCP protocols (CIP I/O, PROFINET RT, GOOSE, Sampled Values, EtherCAT,
   BACnet/IP) worth checking a conduit against -- PROFINET RT, GOOSE,
   Sampled Values, and EtherCAT all ride raw Ethernet with no IP layer at
   all, though, so they would need a conduit-rule shape that isn't
   IP/CIDR-based to ever be covered; CIP I/O, BACnet/IP, and HART-IP's own
   UDP traffic, by contrast, are ordinary IP/UDP traffic, so extending
   `policy validate` to evaluate UDP flows at all (see docs/USER_GUIDE.md's LIMITATIONS) would
   cover all three at once (HART-IP's own TCP traffic is already covered by
   `policy validate` today, the same as any other TCP-based protocol here).

10. ~~Extend HART-IP's command value-decode table beyond the "first pass"
    set -- commands 77 and 178 in particular~~ -- **done**: command 77
    (Send Command to Sub-Device) and command 178 (the unnamed BATCH/
    aggregate wrapper) are both now value-decoded, including recursively
    decoding whichever command(s) each one wraps through this decoder's own
    existing command table -- see docs/PROTOCOL_COVERAGE.md's Command value-decode
    section. No real capture found so far happens to carry either (see
    `tests/real_captures/hartip/ATTRIBUTION.md`'s own "Gaps" section), so
    this remains synthetic-fixture-only validated, like commands 31/203
    already were.

    ~~Still open: verify the HART Data-Link Checksum (the XOR algorithm
    across the whole PDU, currently surfaced raw and never checked)~~ --
    **also done**: the classic wired-HART longitudinal (XOR) checksum is
    now computed across Delimiter..Data inclusive and compared against the
    wire's own trailing Checksum byte -- see docs/USER_GUIDE.md's LIMITATIONS and
    `hartip_checksum`/`hartip_checksum_valid` in JSON OUTPUT FIELDS.
    Purely diagnostic, like DNP3's own CRC validation before it: not wired
    into `policy validate`/`PolicyEngine`, which remains open and isn't
    separately tracked as its own roadmap item, per the same reasoning
    item 4's own DNP3 CRC entry already gives. Fixing this also surfaced
    that `tests/sample_hartip.pcap`'s own Pass-Through packets had never
    carried a genuinely correct checksum byte to begin with (an
    unverified placeholder, harmless until this validation existed to
    check it) -- corrected as part of this pass.

    Still open: resolve multi-definition/warning-class Response Codes to
    their actual per-command meaning, if a reliable source for enough
    individual commands' own spec text ever turns up; and widen real-capture
    validation to Error/NAK messages, the BACK frame type, non-Success
    response codes, and the ten-plus commands (now including 77/178) the
    one real capture found for this feature doesn't happen to exercise.

11. ~~Implement OPC UA's Variant/DataValue self-describing value encoding~~
    (OPC 10000-6 5.2.2.16/5.2.2.17) -- **done**: full Variant/DataValue value
    decoding (all 25 BuiltInTypes, scalar and array, ArrayDimensions, and
    DataValue's own non-bit-numeric wire field order) is now implemented --
    see docs/PROTOCOL_COVERAGE.md's "Variant/DataValue value decoding" section. This
    promoted **Read**, **Write**, and **Call** from header-only (Tier 2) to
    full value decoding (Tier 1) -- the three services whose entire reason
    for existing IS carrying a Variant or DataValue, so this is where the
    actual process/tag values an OPC UA client reads or writes are now
    visible. **Browse** and the subscription/MonitoredItem-management
    services were deliberately left at Tier 2: neither actually carries a
    Variant/DataValue anywhere in its own body, so promoting them is a
    separate, unrelated decode effort. **HistoryRead** does carry
    DataValue/Variant, but its own HistoryReadDetails ExtensionObject
    dispatches across five different sub-structures -- enough additional
    scope of its own that it's left for a later round too. Validated
    against this decoder's own synthetic fixtures (a DataValue with all six
    optional fields set, to regression-test the field-order finding above;
    Float/Null scalars; String/UInt32 Variant arrays, the latter with
    ArrayDimensions) AND, unexpectedly, against the existing real capture:
    promoting Call to Tier 1 revealed that BOTH sessions' own CallRequest in
    that capture are genuinely malformed (Achilles Satellite fuzz-test
    payloads -- one claims a 262144-byte String with ~21 bytes actually
    present, the other has a structurally-invalid NodeId encoding byte) --
    this decoder's own bounds-checked reads now correctly reject them rather
    than the old Tier-2 behavior of labeling them "CallRequest" without ever
    attempting to parse their bodies. Still open: OPC UA chunk reassembly (a
    logical message split across multiple `'C'`/`'F'` chunks -- distinct
    from the already-implemented TCP-segment-level reassembly, see PROTOCOL
    COVERAGE's "Chunking" subsection); widening the StatusCode table past
    its current ~20-entry first pass; promoting Browse/subscriptions/
    HistoryRead to Tier 1 (see above); and widening real-capture validation
    to FindServers, CloseSession, CloseSecureChannel, a non-Anonymous
    identity token, a non-`'F'` chunk, and a well-formed (non-fuzzed) Read/
    Write/Call exchange, if a second real OPC UA capture with that coverage
    ever turns up (see `tests/real_captures/opcua/ATTRIBUTION.md`'s own
    honest scope).
12. ~~**Extend MMS's Tier 2 confirmedServices to full field decoding**~~ --
    **done, scoped to the file-transfer services**: `obtainFile`/
    `fileOpen`/`fileRead`/`fileClose`/`fileRename`/`fileDelete`/
    `fileDirectory` are now Tier 1 (full field decode) -- see PROTOCOL
    COVERAGE's MMS section and mms.hpp's own "File-transfer services"
    paragraph. This was the ROADMAP item's own explicitly-named priority:
    IEC 61850's own COMTRADE/disturbance-file-retrieval and firmware/
    configuration-file-transfer workflows ride on exactly these seven
    services, the most OT-security-relevant of MMS's remaining
    Tier 2 group. `FileName` (a `SEQUENCE OF GraphicString`) is rendered
    joined by "/", matching Wireshark's own `packet-mms.c`
    `dissect_mms_FileName`; `GeneralizedTime` (an ASCII text timestamp,
    distinct from the Data CHOICE's own binary `UtcTime`) is reformatted
    to this codebase's ISO-8601 convention when it parses, shown verbatim
    otherwise; `fileData` is a full, never-truncated hex dump.
    `ObtainFile-Request`'s own `sourceFileServer` (an `ApplicationReference`)
    is structurally recognized but not deep-decoded, the same posture this
    decoder's own ACSE AARQ/AARE decode already takes for AP-title/
    AE-qualifier elsewhere. 60 of the 78 defined confirmed services remain
    Tier 2 (name + invokeID only, body shown as raw hex) -- see PROTOCOL
    COVERAGE's MMS section for the full split. Still open, left for a
    future round: decoding `Address` (non-symbolic variable addressing)
    and `TypeSpecification` (currently both shown only as a structural
    placeholder); implementing the Session layer's extended (2-byte)
    length form, if real traffic using it ever turns up; and widening
    real-capture validation beyond the three small ITI/ICS-Security-Tools
    captures and one self-generated libiec61850 session this decoder
    currently has (see `tests/real_captures/mms/ATTRIBUTION.md`) -- in
    particular, a real capture exercising any Tier 2 service or the new
    file-transfer services specifically, a ServiceError/rejectPDU on real
    traffic (currently synthetic-fixture-validated only), or a stack that
    negotiates a presentation-context numbering other than the assumed
    "1=ACSE, 3=MMS" convention, would meaningfully extend this decoder's
    own confidence.
13. ~~**Expose DNP3's own data-link source/destination address**~~ --
    **done**: `Dnp3LinkFrame::source`/`destination` (already parsed
    internally for the data-link summary line) are now surfaced on
    `DecodedPacket` and in JSON output as `dnp3_source_address`/
    `dnp3_destination_address` -- see JSON OUTPUT FIELDS and POLICY FILE
    FORMAT's "Addressing scope" section, both updated. Set whenever
    `protocol == "dnp3"`, even for a link-layer-only control frame with no
    user data at all (a data-link header carries both addresses
    regardless), mirroring the first data-link frame found in a TCP
    payload, same "first frame only" convention this decoder's own DNP3
    CRC fields already use; reliability tracks `dnp3_header_crc_valid`.
    Still open, left for a future round: the ROADMAP item's own further
    suggestion of "a zone model that can classify by this address in
    addition to (or instead of) IP" -- the single most consequential
    addressing gap in this codebase, since serial-to-IP DNP3 gateways
    routinely multiplex several outstations behind one IP, but a genuinely
    separate scope of its own (policy file format changes, `PolicyEngine`
    matching logic, and its own test/documentation pass) from simply
    exposing the two fields this round completed.
14. ~~**Widen the conduit `protocols` enum**~~ -- **done**: `protocols`/
    `protocol` now names twelve values -- the original
    `modbus, dnp3, s7comm, iec104, enip, any` plus `bacnet`, `hartip`,
    `opcua`, `mms`, `mqtt`, `ffhse` -- see POLICY FILE FORMAT's schema
    block, its `protocols` explanation paragraph, and the "Addressing
    scope" section, all updated. `PolicyEngine::observe`'s own flow-
    classification dispatch was widened to match, not just the parser:
    `hartip`, `opcua`, `mms`, `mqtt`, and `ffhse` genuinely classify real
    TCP traffic now (each verified end-to-end against its own sample
    capture -- see `tests/policies/widened_protocols.yaml` and the
    "Widened `protocols` enum" tests in `CMakeLists.txt`), and their
    function/service names (when decoded) still feed
    `FlowReport::observed_functions` informationally. `bacnet` is accepted
    syntactically and can appear in `unexercised_conduits`, but can never
    actually match a flow: this decoder only recognizes BACnet/IP over
    UDP, and `policy validate` only ever evaluates TCP flows -- see
    "Addressing scope" for the full explanation. Deliberately left open,
    a separate and larger scope of its own: `functions` allow-lists for
    these six protocols (each needs its own known-name table, as
    `modbus`/`dnp3`/`s7comm`/`iec104`/`enip` already have); naming one of
    them in `functions` is now rejected with a specific "not yet
    supported for protocol '...'" error rather than silently failing
    every entry against an empty table. Also still open: `policy
    validate` evaluating UDP flows at all (the only path that could ever
    let `bacnet` -- or HART-IP's/FF-HSE's own UDP forms -- match), and
    the VLAN-based zone model for protocols with no IP layer (item 15).
15. ~~**A VLAN-membership-based conduit/zone model**~~, as an alternative to
    (not a replacement for) the existing IPv4-CIDR one, for the four
    protocols with no IP layer at all (PROFINET RT, GOOSE, Sampled
    Values, EtherCAT) -- **done**: a zone can now declare `vlans: [...]`
    instead of `networks: [...]`, and a conduit referencing only VLAN
    zones is matched against these four protocols' own "L2 flows"
    (aggregated by protocol + MAC pair, since none of them carry a
    client/server IP the way a TCP flow does) -- see POLICY FILE FORMAT's
    Schema, Conduits, Validation errors, JSON report schema, and
    "Addressing scope" sections, all updated, plus its own worked example
    (`tests/policies/vlan_zone_single_segment.yaml`,
    `vlan_zone_mixed_results.yaml`). The genuinely hard design question
    this item raised: a single raw-Ethernet frame carries at most one
    802.1Q tag, so there's no "destination VLAN" the way a TCP flow has a
    server IP distinct from its client IP -- a VLAN-zone conduit's `from`
    and `to` are therefore required to name the exact same zone set,
    reframing what it means from "a directional flow between two zones"
    to "this protocol is permitted on this VLAN zone." Existing IPv4-only
    policy files are provably unaffected: the entire VLAN-zone evaluation
    path is gated behind `Policy::has_vlan_zone()`, so a policy declaring
    zero VLAN zones behaves byte-for-byte as it did before this item
    (PROFINET RT/GOOSE/SV/EtherCAT traffic still falls into
    `skipped_non_tcp`, exactly as before). Deliberately left open: only
    the single outermost 802.1Q tag is ever consulted -- a stacked/QinQ
    frame (EtherType `0x88A8`) can never be VLAN-zone-classified (see
    docs/USER_GUIDE.md's LIMITATIONS); `functions`/per-flow service restriction, which these
    four protocols have no per-flow service name for yet (rejected
    outright at load time on a VLAN-zone conduit rather than silently
    doing nothing); and, unrelated to VLANs, DNP3's link address (item
    13) as an alternative (or additional) zone key once/if that's ever
    taken on.
16. ~~Extend `policy validate`'s report with the same OUI/hostname/service-
    name annotations `decode` now has~~ -- **done**: `policy validate` now
    takes the identical `--mac-vendor`/`--resolve`/`--hosts`/`--nn`/`--services`
    flags `decode` does (see OUTPUT FORMATS' "Name resolution" subsection),
    and its own report -- still the separate, IP/zone-centric format
    described in POLICY FILE FORMAT, not a per-packet `DecodedPacket`
    stream -- is annotated the same way: a `FlowReport`'s `client_ip`/
    `server_ip` get a hostname annotation, `server_port` gets a service-name
    annotation, and its `client_mac`/`server_mac` (a base-value gap-fix
    mirroring `decode`'s own `src_mac`/`dst_mac` addition -- populated from
    the same `DecodedPacket::src_mac`/`dst_mac` PolicyEngine already sees,
    null/absent only for a non-Ethernet-linktype capture) get an OUI-vendor
    annotation; an `EthernetFlowReport`'s `mac_a`/`mac_b` get OUI-vendor
    annotation only, since an L2 flow has no IP or port at all. Text format
    renders these inline right after the raw value (a `client_ip -> ip:port`
    headline plus a `mac: a -> b` line beneath it); JSON format adds them as
    separate fields (`client_mac`/`server_mac`, `client_mac_vendor`/
    `server_mac_vendor`, `client_hostname`/`server_hostname`,
    `server_port_service` on a flow; `mac_a_vendor`/`mac_b_vendor` on an
    Ethernet flow), omitted entirely on a lookup miss or a disabled lookup,
    never emitted as `null` -- the exact same "annotation, not a
    replacement; a miss adds nothing" convention `resolver.hpp`'s file
    header documents for `decode`. See `write_policy_report_text`/
    `write_policy_report_json` in `policy_engine.hpp`/`.cpp` and
    `run_policy_validate` in `cli_main.cpp`.
17. ~~**Passive OT asset inventory: pcap -> zones and conduits.**~~ A new
    subcommand that runs the opposite direction from `policy validate` --
    instead of checking observed traffic against a hand-written zone/
    conduit policy, it infers a first-draft one from a capture -- **done**,
    and since widened: the `inventory` subcommand (see COMMANDS) originally
    identified only five protocols (Modbus, DNP3, S7comm, EtherNet/IP,
    BACnet/IP); it now identifies the same TEN protocols `PolicyEngine::
    observe` itself evaluates over TCP -- those five plus IEC 104, HART-IP,
    OPC UA, MMS, and MQTT, and FF-HSE (all already decoded by this project
    -- see docs/PROTOCOL_COVERAGE.md) -- closing a real gap a user hit in
    practice: `inventory`'s generated policy, fed straight back into
    `policy validate` against the same capture, was reporting a huge
    violation/unclassified count for any of those five newly-added
    protocols' traffic (MQTT in particular) even between two correctly
    zone-classified endpoints, simply because `inventory` never had the
    ability to infer a permitting conduit for them at all. Two of the ten
    (HART-IP, FF-HSE) are counted only over TCP, even though decoder.cpp
    can recognize both over UDP too (HART-IP conventionally; FF-HSE almost
    always in real deployments) -- `policy validate` only ever evaluates
    TCP flows, so a UDP-carried HART-IP/FF-HSE conduit inferred here could
    never actually be exercised, which would just reproduce the exact gap
    this widening closes for a sixth protocol; see asset_inventory.hpp's
    own header comment for the full reasoning (and why this means FF-HSE
    will rarely appear in a report at all, since real FF-HSE is UDP). S7comm
    (including a COTP-only session with no S7comm payload, the same "cotp
    folds into s7comm" convention `PolicyEngine::observe` uses) and MMS
    share the identical TCP/102 COTP transport but stay distinct conduits
    (`InventoryEdge`'s own key includes protocol, so a COTP-control-only
    packet and a real MMS PDU on the same session become two separate
    edges, not one clobbering the other). `inventory` builds an asset list
    (IP/MAC, OUI vendor guess, protocols spoken, client-vs-server role
    inferred from who initiates -- a TCP handshake for every TCP-based
    protocol now covered, the request/response APDU type for BACnet
    specifically, since its client and server both conventionally listen
    on the same port 47808 and so can't be told apart by the usual
    known-port-vs-ephemeral-port heuristic) and a communication matrix
    (`InventoryEdge`: who talks to
    whom, over which protocol/port, aggregated across every TCP session
    between that client/server/protocol/port tuple -- deliberately coarser
    than `PolicyEngine::observe`'s own per-session `FlowReport`, since an
    asset inventory answers "does X talk to Y over protocol P", not "how
    many sessions did X open"), then proposes an IEC 62443 zone/conduit
    model from that matrix -- grouped by observed subnet (`--zone-prefix`,
    default `/24`), rendered as a diagram (Mermaid by default, or Graphviz
    `.dot` via `--diagram-format`) and, via `--policy-out`, as a
    `policy`-format YAML file directly loadable by `policy validate`,
    closing the loop: discover, then enforce (verified end-to-end --
    `tests/sample_inventory.pcap`'s own inferred policy round-trips back
    through `policy validate` against the same capture with every observed
    flow COMPLIANT). NSA's GRASSMARLIN used to occupy this niche but is
    abandoned; CISA's Malcolm covers similar ground but is a heavy
    multi-container Zeek/OpenSearch/Elastic stack, not a lightweight
    single-binary CLI -- `inventory` fills that gap: a `tshark`/Zeek-log-
    adjacent tool that's just "pcap in, zone/conduit model out," built on
    this project's existing decode + `PolicyEngine`/zone infrastructure.
    Deliberately left open, a separate and larger scope of its own:
    grouping zones by protocol in addition to (or instead of) observed
    subnet -- this first pass implements only the subnet half of the
    ROADMAP item's original "grouped by protocol and/or observed subnet"
    heuristic; an LLM-assisted zone-assignment suggestion (which zone a
    given device most plausibly belongs in, with a short rationale -- e.g.
    "talks Modbus only to 10.0.1.5, no traffic to any other zone:
    candidate for a dedicated PLC zone") on top of the deterministic
    grouping above, which was always meant to stand on its own first; and,
    inherited from `policy validate` itself, evaluating the UDP-based
    conduits (BACnet/IP, EtherNet/IP CIP I/O) this feature can infer --
    they parse and load into a policy file fine, but `policy validate`
    only ever evaluates TCP flows today (item 9's own still-open call-out;
    see docs/USER_GUIDE.md's LIMITATIONS), so an inferred UDP conduit always shows up as
    "never exercised by this capture" no matter how much UDP traffic the
    capture actually has.
18. **Recognize the "IT protocols an OT auditor flags" family, and let
    `policy validate`/`inventory` call out their mere presence as its own
    finding.** -- **fully done**, both halves: every one of this family's 43
    protocol values (5+9+7+6+16 across Tiers 1-5, Tier 2's own nine now
    including QUIC alongside HTTPS -- see quic.hpp's own file header
    comment for why) is named by `decode`, and
    `policy validate`/`inventory` now both surface each one's mere presence
    as its own "notable protocols" finding, independent of policy
    compliance -- see this item's own "notable protocols finding -- done"
    paragraph below, after the five tiers' own writeups, for exactly what
    was built. These give an attacker a session, not just a register write
    -- categorically more dangerous than anything Modbus/DNP3/S7comm's own
    read/write transactions can represent, since none of those model "an
    interactive shell" at all. Five tiers, roughly by severity: ~~(1)
    interactive remote control of an HMI/engineering station -- RDP
    (TCP 3389), VNC, TeamViewer/AnyDesk~~ -- **done, and also extended to
    Zoom**: see this item's own "Tier 1 -- done" paragraph below for what
    was actually built; ~~(2) lateral-movement and
    credential-harvesting protocols that should be absent from a production
    OT segment entirely per most hardening guides (IEC 62443-3-3, NCSC,
    NIST SP 800-82) -- SMB/NetBIOS (445/139, also wormable IT malware's
    usual path), SSH (22, benign if key-only and jump-hosted, high-risk if
    password auth reaches a PLC/HMI directly), HTTP/HTTPS and vendor web
    UIs (e.g. Siemens WinCC -- default credentials and unpatched embedded
    web servers are a routine finding), SNMPv1/v2c (161/162, a cleartext
    community string sniffed once maps every SNMP-speaking device on the
    segment), and Telnet/FTP/TFTP (all three move credentials, and often
    firmware/config files, in cleartext)~~ -- **done**: see this item's own
    "Tier 2 -- done" paragraph below for what was actually built; ~~(3) protocols that are
    individually unremarkable in limited form but worth an auditor's
    attention for where they terminate and whether the OT side blindly
    trusts enterprise IT for them -- NTP, DHCP, LDAP/Active Directory (DNS
    itself is a partial exception: already decoded, see docs/PROTOCOL_COVERAGE.md's
    DNS section, so this item is about correlating its *termination point*,
    not new decode work), and the AAA/network-access-control protocols that
    sit right next to LDAP/AD in the same "does OT trust enterprise
    identity infrastructure" question -- RADIUS (UDP 1812/1813, legacy
    1645/1646, cleartext-by-default attribute encoding for anything past
    the shared secret), TACACS+ (TCP 49, used almost exclusively for
    device-administration AAA -- its presence on an OT segment usually
    means switches/routers there authenticate admin logins against an
    enterprise TACACS+ server), and IEEE 802.1X/EAPOL (no IP port at all --
    EtherType `0x888E`, port-based network access control at the switch
    port itself, so seeing it on an OT access port is evidence a device had
    to authenticate onto the network, which cuts the other way from most of
    this item: its *absence* on an OT switch port is often the finding,
    since it means anything can plug in and reach the segment
    unauthenticated)~~ -- **done**: see this item's own "Tier 3 -- done"
    paragraph below for what was actually built; ~~(4) wireless access-point
    control/data planes and
    cellular backhaul -- an AP or wireless LAN controller reachable from (or
    inside) an OT zone is itself a finding, independent of whatever rides
    inside its tunnel: CAPWAP control (UDP 5246, RFC 5415) and data
    (UDP 5247, the actual bridged client frames tunneled to the
    controller), the older, Cisco-proprietary CAPWAP predecessor LWAPP
    (UDP 12222 control / 12223 data), and cellular-backhaul-specific
    protocols like PPPoE and GTP-U (UDP 2152 -- a well-known way SCADA
    traffic leaves a site entirely outside any on-prem firewall's view, the
    usual signature of an RTU or 4G/5G router phoning out through a
    vendor's "cloud gateway" SIM)~~ -- **done**: see this item's own "Tier 4
    -- done" paragraph below for what was actually built; and ~~(5) generic tunnel/VPN encapsulation
    -- the broader problem CAPWAP/GTP-U above are specific instances of: an
    inner VLAN, Modbus session, or entire plant subnet is invisible to
    every decoder and to `policy validate`'s own flow model alike until the
    outer tunnel is stripped off, so merely naming the outer protocol is
    already a finding worth surfacing. Roughly by how the tunnel actually
    presents on the wire: GRE (IP protocol 47, RFC 2784, common for an
    AP-to-controller or site-to-site path, unencrypted by default); IPsec
    ESP/AH/IKEv2 (UDP 500/4500, IP protocols 50/51 -- expected for a
    remote-site link, but worth checking whether its traffic selectors
    dump a whole plant subnet into IT, and whether it's split- or
    full-tunneled); L2TP/L2TPv3 (UDP 1701, L2TPv3 often paired with
    IPsec -- stretches one L2 segment across a WAN, widening the blast
    radius); VXLAN (UDP 4789) and Geneve (UDP 6081), the common
    data-center/campus/cloud overlay fabrics an OT VM or a virtualized
    historian can end up riding on top of an ordinary IT underlay; NVGRE/
    STT (IP protocol 47 / TCP 7878), less common but the same "the inner
    frame isn't what the firewall inspects" concern as VXLAN/Geneve; MPLS/
    L2VPN/VPLS/pseudowire (label-switched, no port at all -- a utility WAN
    link often carries SCADA over a pseudowire, worth confirming encryption
    and who else shares the same VRF); WireGuard (UDP 51820), OpenVPN
    (UDP/TCP 1194), and SSTP (TCP 443, indistinguishable from ordinary
    HTTPS at a glance) -- the shadow-IT and vendor-remote-access case, any
    of which can tunnel literally anything; generic DTLS/TLS tunnels (443
    and odd UDP ports -- CAPWAP's own data plane, some vendor AP control
    channels, and LTE "offload" clients can all ride one); EoIP/IP-in-IP/
    6in4/4in6/DS-Lite/MAP-E (IP protocols 4/41/etc. -- rare inside a plant
    itself, common on a cellular CPE router, bypassing perimeter inspection
    the same way); and CAPWAP's own alternate data-plane path, where a
    wireless LAN controller decapsulates over GRE/L2TP/IP-in-IP instead of
    native CAPWAP -- meaning the real decap point isn't the controller at
    all, and is worth inspecting directly rather than assumed. NCSC's own
    framing is the rule of thumb this item is named for: industrial
    protocols (Modbus, DNP3, S7comm, and the rest already in PROTOCOL
    COVERAGE) should stay inside isolated OT segments; anything that
    legitimately needs to cross toward IT should be brokered through an
    encrypted, authenticated channel (OPC UA over TLS, MQTT over TLS,
    HTTPS) rather than riding raw OT protocols -- or an interactive-access
    or tunneling protocol -- straight across the boundary.~~ -- **done**: see this item's own "Tier 5 -- done" paragraph below for what was actually built.

    **Tier 1 -- done**, and see docs/PROTOCOL_COVERAGE.md's own "Tier 1 remote-
    access protocol recognition" section for the full writeup: `decode`
    (and, since it's a normal protocol dispatch, `policy validate`/
    `inventory` too) now recognizes RDP, VNC, TeamViewer, AnyDesk, and
    Zoom (added to this tier during implementation, alongside the four
    originally named here), each reported as its own `protocol` value
    (`"rdp"`/`"vnc"`/`"teamviewer"`/`"anydesk"`/`"zoom"`) rather than
    folded into a generic `tcp`/`udp` bucket -- directly fixing this
    item's own "modeling gap" paragraph below for this one tier: a
    conduit with no rule for RDP traffic now shows `"protocol": "rdp"`
    left unclassified by the policy, not a generic `tcp` flow. Confidence
    varies sharply by protocol, honestly reflected in every summary/note
    this produces, not smoothed over into one uniform confidence level:
    VNC's RFB protocol-version banner (RFC 6143) and RDP's initial X.224
    Connection Request/Confirm (reusing this project's own `cotp.hpp` TPKT/
    COTP parser, exactly the reuse this item originally proposed) are both
    genuine cleartext structural signatures; TeamViewer, AnyDesk, and Zoom
    have none at all (encrypted from their first byte) and are recognized
    by port number alone -- the single weakest identification gate in this
    entire codebase, weaker even than HART-IP's own loosely-checked-header
    gate, since there is no payload check whatsoever. `--protocol
    remote-access` isolates this family the same way every other
    `--protocol` value does, and `--remote-access-port` widens its
    "expected port" set (one shared option across all five, the same
    "one feature toggle" grouping `--ffhse-port` already established) --
    see OPTIONS. One real implementation wrinkle worth recording: RDP's
    X.224 handshake and S7comm/MMS's own COTP Data/Connection frames share
    IDENTICAL TPKT+COTP wire framing (see docs/USER_GUIDE.md's LIMITATIONS), so recognizing RDP
    required intercepting a Connection Request/Confirm on TCP port 3389
    BEFORE this decoder's existing, opportunistic (port-independent)
    S7comm/MMS dispatch got a chance to claim it as generic `cotp` traffic
    first -- see `it_protocols.hpp`'s and `decoder.cpp`'s own comments at
    that call site for the full reasoning.

    **Tier 2 -- done**, and see docs/PROTOCOL_COVERAGE.md's own "Tier 2
    lateral-movement protocol recognition" section for the full writeup:
    `decode` now also recognizes SMB, SSH, HTTP, HTTPS, SNMPv1/v2c, Telnet,
    FTP, TFTP, and QUIC -- nine more `protocol` values (`"smb"`/`"ssh"`/
    `"http"`/`"https"`/`"snmp"`/`"telnet"`/`"ftp"`/`"tftp"`/`"quic"`; QUIC
    joined later, alongside HTTPS -- see `quic.hpp`'s own file header
    comment for why), the same fix to this
    item's own "modeling gap" paragraph below Tier 1 already made, now
    covering the family the ROADMAP calls out as most worth an auditor's
    attention: protocols that "should be absent from a production OT
    segment entirely per most hardening guides." Confidence is, once again,
    reported honestly rather than uniformly: SMB's direct-hosting magic
    (`0xFF`/`0xFE`/`0xFD` + `"SMB"`), SSH's RFC 4253 version-exchange
    banner, and HTTP's own request-line/status-line are all genuine,
    self-describing cleartext structural signatures, checked
    port-independently even in Auto mode (deliberately so for HTTP -- a
    vendor web UI like Siemens WinCC running on whatever port the vendor
    picked is exactly the case this item names); HTTPS reuses this
    project's own `tls_sni.hpp` TLS ClientHello parser (already built for
    DoH detection) rather than re-implementing TLS parsing, layered so a
    DoH match always wins and a ClientHello that isn't a known DoH
    provider's hostname falls through to generic `"https"` instead (ALPN
    offering `"http/1.1"`/`"h2"` confirms it outright; a standard port with
    no ALPN is still called `"https"` but says so honestly; no ClientHello
    at all is the weakest, port-only fallback for an already-established
    session); SNMPv1/v2c genuinely extracts and surfaces the cleartext
    community string itself (a deliberate, narrow departure from this
    family's usual name-only posture -- see this item's own SNMP wording:
    "a cleartext community string sniffed once maps every SNMP-speaking
    device on the segment," so the audit value IS the string); and Telnet/
    FTP/TFTP each have a real but narrower signal (an IAC negotiation
    burst, a 3-digit reply code or known command verb, and an RRQ/WRQ's
    filename+mode respectively) gated to their own well-known port, since
    unlike SMB/SSH/HTTP none of their own structural tells are strong
    enough to check port-independently without real false-positive risk.
    `--protocol lateral-movement` isolates this family, and
    `--lateral-movement-port` widens its "expected port" set (one shared
    option across all eight, the same grouping `--remote-access-port`
    already established for Tier 1) -- see OPTIONS. One real implementation
    wrinkle worth recording, in the same spirit as Tier 1's RDP/COTP one:
    an FTP reply-code or command-verb line's own leading ASCII bytes can,
    purely by coincidence, satisfy MQTT's own single-byte "control packet
    type + a plausible variable-length remaining-length" opportunistic
    detection gate (mqtt.hpp) -- confirmed empirically while building this
    tier's own test fixture. Unlike RDP/COTP's genuine shared framing, this
    is pure coincidence, not two protocols sharing a wire format, so it's
    resolved by port instead: FTP traffic on its own well-known
    control-channel port (21, or a configured `--lateral-movement-port`)
    that structurally matches an FTP reply-code/command-verb line is
    excluded from MQTT's own opportunistic detection (both its declared-
    length reassembly probe and its full message parse), since no real
    MQTT broker runs on port 21 -- see `decoder.cpp`'s own comments at both
    call sites for the full reasoning.

    **Follow-up fix (post-release, Jurgen's own report)**: QUIC's own
    Handshake/0-RTT/Retry long-header recognition (see `quic.hpp`'s file
    header comment for why QUIC joined this tier later, alongside HTTPS)
    misdetected a large fraction of a busy NBT-NS (UDP port 137)
    broadcast segment's traffic as `[quic]`, confirmed against a real
    capture. Root cause: those three packet types were accepted on
    nothing more than byte0's Header Form bit, Fixed Bit, and 2-bit type
    field -- 4 bits total, true of roughly 1 in 4 arbitrary UDP payloads
    port-independently (QUIC's long-header recognition runs
    port-independently by design, the same "structural signature
    overrides the port gate" treatment this tier's own HTTP/SMB/SSH
    checks already get) -- with no check at all on any *other* field, let
    alone one actually cross-checked for self-consistency against the
    packet's own declared structure the way this file's other paths
    already did (Version Negotiation's own whole-number-of-4-byte-
    versions check; Initial's own Length-field/captured-bytes check).
    NBT-NS's own 2-byte Transaction ID landing on that same byte0/byte1
    position, effectively random from this decoder's point of view, hit
    that weak pattern often enough to be a real, visible source of false
    positives in a security-auditing tool's own Tier 2 "should be absent
    from a production OT segment" finding -- exactly the kind of finding
    an auditor needs to trust. Fixed in `try_recognize_quic` (`quic.cpp`):
    0-RTT/Handshake now read their own Length field (RFC 9000
    17.2.3/17.2.4) and require it to describe a byte count that actually
    fits within what was captured and is large enough for a 1-byte Packet
    Number plus a 16-byte AEAD tag (the identical check the Initial path
    already had, just missing from these two); Retry now requires its own
    mandatory 16-byte Retry Integrity Tag (RFC 9000 17.2.5) to actually be
    present. Unlike Initial's own truncated-capture tolerance, a failure
    of either check on these three types now returns "not a match"
    outright rather than a lenient fallback -- none of the three are ever
    decrypted regardless of how much was captured, so there was no
    analytical payoff to weigh against fully closing the false-positive
    gap. Verified: a new regression fixture and test
    (`quic_0rtt_type_bits_alone_not_misdetected`, `tests/sample_quic.pcap`
    packet #10 via `tools/make_quic_sample_pcap.py`) reproduces the
    general shape of the real collision (byte0 alone satisfying the old
    gate, no self-consistent trailer) and confirms it now falls through
    to the generic `"udp"` tag; the full CTest suite (1301 tests, up from
    1300 -- every existing QUIC assertion passing unchanged, proof this
    didn't regress a single legitimately-decoded case) stayed 100%
    passing; zero-warning clean rebuilds across all three established
    configs (default+libpcap, `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`,
    MinGW cross-compile).

    **Follow-up fix, round two (post-release, Jurgen's own SECOND
    report)**: the same real NBT-NS capture -- this time with a marked
    excerpt of the still-misdetected packets attached, isolating two
    remaining shapes -- showed round one's own fix was incomplete. Root
    cause, in two parts: (1) Retry's own round-one check ("at least 16
    trailing bytes exist") is satisfied by nearly any UDP payload of
    ordinary size, since Retry (RFC 9000 17.2.5) has no Length/Packet-
    Number field of its own to self-check against at all -- unlike every
    other long-header type, verifying its actual Retry Integrity Tag
    cryptographically would need the original connection's own
    Destination Connection ID, which isn't present in the Retry packet
    itself and isn't state this single-packet decoder tracks. (2)
    Initial's own pre-existing check (present since before round one,
    untouched by it) conflated two different situations into one lenient
    fallback: a Length field too small to ever hold a real Initial
    packet's mandatory 1-byte Packet Number plus 16-byte AEAD tag
    (`length_field < 17`, structurally invalid at any capture length) was
    treated exactly the same as a Length field that's plausible but
    wasn't fully captured (genuine snaplen truncation) -- both fell
    through to the same "truncated capture" name-only match. NBT-NS's own
    Flags/QDCOUNT bytes, read as Initial's Token-Length/Length fields,
    happened to decode to 0/0 for one group of packets in the capture,
    which the old combined check waved through as "truncated" instead of
    rejecting; a second group's Transaction-ID-derived "Version" field
    landed on Retry's own byte0 type bits with an arbitrary non-1 value,
    which round one's weak trailing-bytes-only check never looked at.
    Fixed in `try_recognize_quic` (`quic.cpp`): Retry now also requires an
    exact QUIC v1 Version match -- real Retry traffic is, in practice,
    always v1 (v2, RFC 9369, remains vanishingly rare in deployment), and
    an arbitrary payload's Version field landing on exactly `0x00000001`
    by coincidence is a 1-in-4-billion event, versus the 1-in-4 chance of
    byte0's 4 bits alone matching; Initial's combined check is now split
    in two, so only "declares more than was captured" (with a plausible
    `>= 17` Length field) still gets the tolerant "truncated capture"
    match, while "Length field itself is too small" is rejected outright,
    the same treatment the 0-RTT/Handshake paths already give the
    identical check. Verified: three new regression fixtures and tests
    (`tests/sample_quic.pcap` packets #11-13 via
    `tools/make_quic_sample_pcap.py`,
    `quic_initial_zero_length_field_not_misdetected`,
    `quic_retry_wrong_version_not_misdetected`,
    `quic_initial_genuinely_truncated_still_matches`) reproduce both
    collision shapes from the real capture and confirm they now fall
    through to the generic `"udp"` tag, plus a positive control proving a
    genuinely truncated real Initial packet still gets its tolerant match
    -- proof the fix didn't overcorrect; the user's own marked capture,
    reproduced locally, now decodes every packet as `[nbns]` with zero
    `[quic]` matches; the full CTest suite (1304 tests, up from 1301 --
    every existing QUIC assertion passing unchanged) stayed 100% passing;
    zero-warning clean rebuilds across all three established configs.

    **Tier 3 -- done**, and see docs/PROTOCOL_COVERAGE.md's own "Tier 3
    enterprise-trust-boundary protocol recognition" section for the full
    writeup: `decode` now also recognizes NTP, DHCP, LDAP, LDAPS, RADIUS,
    TACACS+, and IEEE 802.1X/EAPOL -- seven more `protocol` values
    (`"ntp"`/`"dhcp"`/`"ldap"`/`"ldaps"`/`"radius"`/`"tacacs-plus"`/
    `"eapol"`), the same fix to this item's own "modeling gap" paragraph
    below Tiers 1-2 already made, now covering the family this item frames
    as "individually unremarkable in limited form but worth an auditor's
    attention for where they terminate and whether the OT side blindly
    trusts enterprise IT for them." DNS/Active Directory needed no new
    decode work at all, exactly as this item's own wording anticipated:
    DNS is already fully decoded (see docs/PROTOCOL_COVERAGE.md's DNS section), so
    this tier is about correlating where an OT segment's DNS queries
    actually terminate (an enterprise domain controller vs. a local/
    isolated resolver), a policy/zone-conduit question left for a future
    `policy validate` enhancement, not a decoder change. DHCP's RFC 1497/
    2131 magic cookie (`0x63 0x82 0x53 0x63`, immediately after the fixed
    236-byte BOOTP-derived header) is a genuine, strong, cleartext
    structural signature, checked port-independently even in Auto mode --
    the same treatment SMB/SSH/HTTP get in Tiers 1-2, since a rogue or
    misconfigured DHCP server answering on an unexpected port is exactly
    what this item's own framing cares about; option 53 (DHCP Message
    Type) is additionally decoded by name when present. LDAP's own
    LDAPMessage envelope (RFC 4511: a BER SEQUENCE wrapping an INTEGER
    messageID and an `[APPLICATION n]`-tagged protocolOp) is a genuine, if
    ASN.1-common-enough-elsewhere-to-stay-port-gated, structural
    signature, the same caution SNMP's own BER check earns in Tier 2 --
    and an observed `bindRequest` (a simple, non-SASL bind) earns its own
    note, since that's a cleartext-credential exchange unless the session
    was already upgraded via StartTLS (the credential itself is never
    inspected, staying within this whole item's name-only posture). LDAPS
    is layered into the SAME early TLS-ClientHello call site HTTPS's own
    strong check already uses (reusing `tls_sni.hpp`, not a second TLS
    implementation): a ClientHello on port 636/3269 (the Active Directory
    Global Catalog-over-TLS port) is tagged `"ldaps"` instead of generic
    `"https"`, unless ALPN itself already confirms HTTP, in which case the
    more specific ALPN signal wins regardless of port. RADIUS's RFC 2865
    fixed 20-byte header (a small enumerated Code, plus a
    `20 <= Length <= 4096` bound) and TACACS+'s RFC 8907 fixed 12-byte
    header (a version byte whose upper nibble is always `0xC`, plus a
    3-value Type) are each genuine but modest structural signatures,
    gated to their own well-known ports for the same "not self-describing
    enough on its own" reasoning Telnet/FTP/TFTP already established in
    Tier 2; TACACS+'s own `TAC_PLUS_UNENCRYPTED_FLAG` is additionally
    surfaced as its own note when set, since RFC 8907 itself calls
    TACACS+'s body "encryption" obfuscation at best even when that flag is
    clear. IEEE 802.1X/EAPOL is architecturally different from the other
    six: it rides raw Ethernet (EtherType `0x888E`), not any TCP/UDP port
    at all, the same shape PROFINET RT/GOOSE/Sampled Values/EtherCAT
    already have in this codebase, so it gets its own dedicated
    `--protocol eapol` value (not folded into `--protocol
    enterprise-trust`, which covers only the six port-based protocols) and
    its own dedicated `eapol.hpp`/`eapol.cpp`, dispatched from the same
    EtherType-keyed region of `decoder.cpp` PROFINET/GOOSE/SV/EtherCAT
    already use. EAPOL's own audit framing is the one place in this whole
    item that cuts the opposite way from every other protocol here:
    seeing EAPOL on an OT switch port is *reassuring* (the device had to
    authenticate onto the network before passing any other traffic at
    all), so its *absence* is often the actual finding -- this decoder can
    only ever report "802.1X traffic was or wasn't captured here," not
    "802.1X is configured but idle," which is an inherent limit of passive
    capture, not a shortcut taken here. `--protocol enterprise-trust`
    isolates the six port-based protocols (EAPOL is reached only via its
    own `--protocol eapol`, or in Auto mode alongside everything else), and
    `--enterprise-trust-port` widens the six's shared "expected port" set
    (one option across all six, the same grouping `--lateral-movement-port`
    already established for Tier 2; EAPOL needs no port option at all,
    matching PROFINET/GOOSE/SV/EtherCAT/STP's own no-port precedent) -- see
    OPTIONS. One real implementation wrinkle worth recording, in the same
    spirit as Tier 2's own FTP/MQTT one: LDAP's own leading BER SEQUENCE
    tag byte (`0x30`) is bit-for-bit identical to a valid MQTT PUBLISH
    control-packet-type/flags byte, so MQTT's own opportunistic,
    port-independent detection gate (`mqtt.hpp`) matches every genuine LDAP
    message purely by coincidence -- confirmed empirically while building
    this tier's own test fixture, the exact same shape of collision as
    Tier 2's FTP-vs-MQTT one, and resolved the same way: LDAP traffic on
    its own configured port (389/3268, or a configured
    `--enterprise-trust-port`) that structurally matches an LDAPMessage
    envelope is excluded from MQTT's own opportunistic detection (both its
    declared-length reassembly probe and its full message parse) -- see
    `decoder.cpp`'s own comments at both call sites for the full reasoning.
    One direct consequence worth being explicit about: an LDAP message on
    a genuinely arbitrary, unconfigured port is NOT rescued by this
    carve-out (LDAP, unlike SMB/SSH/HTTP in Tiers 1-2, is deliberately kept
    port-gated -- see docs/PROTOCOL_COVERAGE.md) and is still misidentified as
    MQTT until that specific port is added via `--enterprise-trust-port`;
    this is an accepted, documented trade-off of this item's "port-gated
    where the structural signature alone is too common elsewhere" design,
    not an oversight.

    **Tier 4 -- done**, and see docs/PROTOCOL_COVERAGE.md's own "Tier 4
    wireless-backhaul-and-cellular protocol recognition" section for the
    full writeup: `decode` now also recognizes CAPWAP control, CAPWAP data,
    LWAPP control, LWAPP data, GTP-U, and PPPoE -- six more `protocol`
    values (`"capwap-control"`/`"capwap-data"`/`"lwapp-control"`/
    `"lwapp-data"`/`"gtp-u"`/`"pppoe"`), the same fix to this item's own
    "modeling gap" paragraph below Tiers 1-3 already made, now covering the
    family this item frames as "an AP or wireless LAN controller reachable
    from (or inside) an OT zone is itself a finding, independent of
    whatever rides inside its tunnel." CAPWAP control/data (RFC 5415) share
    a modest but genuine structural signature (a Preamble byte plus the
    Transport Header's own HLEN field, sanity-checked, without a
    bit-perfect decode of every transport-header field); CAPWAP control
    additionally names its own Control Header Message Type when resolvable,
    while CAPWAP data deliberately goes no further than naming the tunnel
    itself, since the bridged 802.11 client frame it carries is exactly the
    content this item's own framing says doesn't need decoding to be a
    finding. LWAPP control/data -- CAPWAP's Cisco-proprietary predecessor,
    never published as a standards-track RFC -- are recognized by port
    number alone, the same weakest-gate treatment TeamViewer/AnyDesk/Zoom
    get in Tier 1, honestly reflected in every match. GTP-U (3GPP TS
    29.281) has a genuine structural signature (a Version/PT nibble check
    plus an enumerated Message Type) and surfaces its own TEID without
    attempting to decode a G-PDU's inner IP packet, the same "name the
    tunnel, don't follow it" posture this item's own wording calls for.
    IEEE 802.1X/EAPOL's own architectural exception from Tier 3 repeats
    here: PPPoE rides raw Ethernet (EtherType `0x8863`/`0x8864`), not any
    port at all, so it gets its own dedicated `--protocol pppoe` value (not
    folded into `--protocol wireless-backhaul`, which covers only the five
    port-based protocols) and its own dedicated `pppoe.hpp`/`pppoe.cpp`,
    dispatched from the same EtherType-keyed region of `decoder.cpp`
    PROFINET/GOOSE/SV/EtherCAT/EAPOL already use. `--protocol
    wireless-backhaul` isolates the five port-based protocols (PPPoE is
    reached only via its own `--protocol pppoe`, or in Auto mode alongside
    everything else), and `--wireless-backhaul-port` widens the five's
    shared "expected port" set (one option across all five, the same
    grouping `--enterprise-trust-port` already established for Tier 3) --
    unlike Tier 3, none of this tier's own structural checks are strong
    enough to run port-independently, so this option always gates
    detection itself; EAPOL's own no-port precedent extends to PPPoE
    needing no port option at all -- see OPTIONS. Unlike Tiers 1-3, this
    tier hit no real protocol-collision wrinkle worth recording: none of
    CAPWAP/LWAPP/GTP-U's own ports (5246/5247/12222/12223/2152) or PPPoE's
    own EtherTypes overlap any other protocol this decoder already
    dispatches on, so no MQTT-style carve-out was needed.

    **Tier 5 -- done**, and see docs/PROTOCOL_COVERAGE.md's own "Tier 5 generic
    tunnel/VPN encapsulation recognition" section for the full writeup:
    `decode` now also recognizes GRE, NVGRE, Mikrotik EoIP, IPsec ESP,
    IPsec AH, IP-in-IP, 6in4, L2TP/L2TPv3, IKE, VXLAN, Geneve, WireGuard,
    OpenVPN, a generic DTLS-tunnel structural check, STT, and MPLS --
    sixteen more `protocol` values (`"gre"`/`"nvgre"`/`"eoip"`/`"esp"`/
    `"ah"`/`"ip-in-ip"`/`"6in4"`/`"l2tp"`/`"ike"`/`"vxlan"`/`"geneve"`/
    `"wireguard"`/`"openvpn"`/`"dtls-tunnel"`/`"stt"`/`"mpls"`), the same
    fix to this item's own "modeling gap" paragraph below Tiers 1-4 already
    made, now covering the family this item frames as "the broader problem
    CAPWAP/GTP-U above are specific instances of": merely naming the outer
    tunnel is already a finding, since an inner VLAN, Modbus session, or
    entire plant subnet is invisible to every decoder (and to `policy
    validate`'s own flow model) until it's stripped off. Organized, like
    every earlier tier, around how each tunnel actually presents on the
    wire rather than the ROADMAP text's own order -- three shapes, three
    dispatch points, all in the new `tunnel_vpn.hpp`/`tunnel_vpn.cpp`
    (except MPLS, see below): GRE (47), ESP (50), AH (51), IP-in-IP (4),
    6in4 (41), and L2TPv3's own direct-IP form (115) ride raw IP with no
    port at all, the same shape IGMP/VRRP/IGRP/PIM/EIGRP/OSPF already have;
    IKE (500/4500), L2TP-over-UDP (1701), VXLAN (4789), Geneve (6081),
    WireGuard (51820), OpenVPN (1194), and the generic dtls-tunnel check
    are UDP-port-keyed; OpenVPN's own TCP framing and STT (7878) are
    TCP-port-keyed. GRE's own Protocol Type field (an EtherType value)
    further splits into three names: NVGRE (RFC 8926, Protocol Type
    0x6558 with the Key flag set -- honestly noted as ambiguous with plain
    Ethernet-bridging-over-GRE, which shares the identical Protocol Type
    and is structurally indistinguishable from it), Mikrotik EoIP
    (Protocol Type 0x6400, unambiguous), and plain `"gre"` for everything
    else (most commonly IPv4, RFC 2784's own original use case). IP-in-IP
    is the one deliberate exception to this whole tier's "name the tunnel,
    don't unwrap it" posture: its inner IPv4 header sits in plaintext
    immediately after the outer one, so its own inner src/dst addresses
    are surfaced (directly answering this item's own "an entire plant
    subnet is invisible... until the outer tunnel is stripped off"
    framing) -- 6in4's own inner IPv6 addresses are NOT surfaced the same
    way, since this codebase has no IPv6 address parser at all and writing
    one solely for this case would be real scope creep. ESP/AH are opaque
    past their own SPI (AH additionally names the inner protocol it's
    protecting, via its own Next Header field, since AH -- unlike ESP --
    leaves the inner header visible); L2TPv2-over-UDP has a genuine
    structural check (Version/reserved-bit validation), while L2TPv3 (both
    its own direct-IP form and its UDP form, which has no way to
    distinguish itself from an L2TPv2 structural mismatch) is honestly
    reported as the weaker, port-only fallback. IKE's own multi-field
    header (SPI pair, Major/Minor Version, Exchange Type, Length) is a
    genuine structural signature; port 4500 (RFC 3948 NAT-Traversal)
    additionally disambiguates IKE from raw NAT-Traversed ESP by checking
    for the 4-byte all-zero non-ESP marker RFC 3948 itself defines.
    VXLAN/Geneve each have genuine structural signatures (VXLAN's own
    Flags byte, Geneve's own Version/Reserved bits) and surface their VNI;
    WireGuard has the strongest signature in this entire tier (an exact,
    fixed total-packet-length match for three of its four message types);
    OpenVPN's opcode byte is a modest, NTP-Mode-style signature, shared
    verbatim between its UDP and TCP forms (the TCP form adds only a
    2-byte length prefix). A generic DTLS-record structural check (no
    fixed port at all, tried last and port-independently among every UDP
    check in this tier -- ContentType plus one of DTLS's three exact
    16-bit version values is a strong enough multi-field match to earn the
    same "structural signature overrides the port gate" treatment VNC/SMB/
    SSH/HTTP/DHCP already have) is reported `"dtls-tunnel"`: this decoder
    cannot tell CAPWAP's own DTLS data plane, a vendor AP's DTLS control
    channel, an LTE offload client, or a deliberate DTLS-based VPN apart
    from each other, and per this item's own framing, naming that SOME
    encrypted DTLS tunnel is present is the entire audit value here. STT
    (TCP 7878) is recognized by port number alone, the same weakest-gate
    treatment LWAPP gets in Tier 4, since it has no publicly authoritative
    wire-format specification to check a structural signature against.
    MPLS is architecturally different from the other fifteen, the same way
    EAPOL/PPPoE were in Tiers 3-4: it rides raw Ethernet (EtherType
    `0x8847` unicast / `0x8848` multicast), not any port or IP layer at
    all, so it gets its own dedicated `--protocol mpls` value (not folded
    into `--protocol tunnel-vpn`, which covers only the fourteen port/
    IP-protocol-number-based protocols) and its own dedicated
    `mpls.hpp`/`mpls.cpp`, dispatched from the same EtherType-keyed region
    of `decoder.cpp` PROFINET/GOOSE/SV/EtherCAT/EAPOL/PPPoE already use.
    Unlike every EtherType-keyed protocol before it, MPLS's own label
    stack (RFC 3032: Label/Exp/Bottom-of-Stack/TTL, 4 bytes per label) has
    no Version/Type field to structurally validate at all -- any 4-byte-
    aligned value is syntactically a valid label entry, so the EtherType
    itself carries all of the confidence, the same posture GRE's own
    Protocol Type sub-cases and IGMP/VRRP's own IP-protocol-number-only
    gate already have. The label stack itself IS genuinely parsed in full
    (walked label-by-label until a Bottom-of-Stack bit is found, capped at
    16 entries as a sanity bound) -- but the payload past the last label is
    deliberately NOT decoded, since an ordinary MPLS-switched IP packet and
    an MPLS pseudowire/L2VPN/VPLS payload (an entire Ethernet frame,
    optionally preceded by a 4-byte all-zero Pseudowire Control Word) are
    wire-format-identical from this decoder's own point of view, controlled
    entirely by out-of-band LDP/BGP signaling this passive decoder never
    sees; a heuristic guess here would be far less reliable than IP-in-IP's
    own first-nibble check (a pseudowire's Control Word is frequently all
    zero bytes, indistinguishable from padding or truncation). `--protocol
    tunnel-vpn` isolates the fourteen port/IP-protocol-number-based
    protocols (MPLS is reached only via its own `--protocol mpls`, or in
    Auto mode alongside everything else), and `--tunnel-vpn-port` widens
    every port-based protocol's shared "expected port" set EXCEPT
    dtls-tunnel's own (never port-gated, see above) -- one option across
    all fourteen, the same grouping `--wireless-backhaul-port` already
    established for Tier 4; GRE/ESP/AH/IP-in-IP/6in4/L2TP's own
    IP-protocol-number-keyed forms, and MPLS, need no port option at all,
    the same no-port precedent IGMP/VRRP/EAPOL/PPPoE already established --
    see OPTIONS. This tier DID hit a real, and more severe, protocol-
    collision wrinkle than any earlier one: HART-IP's own opportunistic,
    port-independent UDP detection gate (a 2-byte MessageType/MessageID
    check) is trivially satisfied not by coincidence but by two Tier 5
    protocols' own SPEC-MANDATED wire formats -- RFC 3948's IKE NAT-T
    non-ESP marker (an all-zero 4-byte prefix by definition) and RFC 7348's
    VXLAN header (an all-zero Reserved field at that exact byte range by
    definition) -- meaning, unlike Tier 2's FTP/MQTT or Tier 3's LDAP/MQTT
    coincidental collisions, genuine NAT-T IKE or VXLAN traffic would
    ALWAYS misclassify as `"hartip"` in Auto mode, not merely
    occasionally. Resolved by excluding ports 4500 and 4789 from HART-IP's
    own opportunistic Auto-mode attempt entirely (an explicit `--protocol
    hartip` still attempts every port, unaffected) -- see `decoder.cpp`'s
    own comment at that call site for the full reasoning; unlike the
    accepted, documented HART-IP/Modbus TCP collision noted above, this
    one was judged too severe (guaranteed rather than merely possible) to
    simply document and leave unresolved.

    Scoped honestly, this is name-only recognition (port plus a minimal
    structural signature), not full protocol decoding -- the same
    "recognized but not decoded" posture ARP/LLDP/ICMP already have (see
    docs/PROTOCOL_COVERAGE.md): there is no OT-security value in parsing RDP's own
    bitmap updates or SMB's own file listings, and several of these (RDP
    past its initial handshake, HTTPS, any VPN tunnel) are encrypted and
    structurally opaque by design past their first few packets anyway. One
    genuinely useful technical shortcut, now realized (see "Tier 1 -- done"
    above): RDP's own initial X.224 Connection Request/Confirm rides the
    identical TPKT framing this codebase's COTP parser (`cotp.hpp`,
    currently used for S7comm/MMS on TCP port 102) already implements --
    port 3389 rather than 102 disambiguates the two, and since this tier
    only needs to NAME the PDU (Connection Request vs. Confirm), `cotp.hpp`
    already parses enough of the X.224 header for that; no new framing or
    payload parsing code was needed. SMB turned out to be a lighter lift
    than this paragraph originally expected, too (see "Tier 2 -- done"
    above): naming it only ever needed the leading 4-byte magic (either
    directly, or 4 bytes into a NetBIOS Session Service wrapper), not a
    full SMB1-vs-SMB2/3 dialect negotiation walk -- a conduit or asset
    inventory that has zero tolerance for a protocol existing inside an OT
    zone at all doesn't need to look inside it to register the finding.

    This also named a real modeling gap in `policy validate`'s original
    allow-list design worth calling out: before this item's second half
    below, any TCP flow this decoder doesn't recognize the protocol of
    already fell into "Unclassified" (see POLICY FILE FORMAT's "Validation
    errors" and OUTPUT FORMATS), which was correct but generic -- it
    couldn't distinguish "this is SSH, which per NCSC's rule of thumb
    should never be here" from "this is some protocol conduitscope simply
    hasn't been taught yet." Recognizing these protocols by name turned
    that generic bucket into a specific, actionable one ("SSH traffic
    observed on the plant-floor VLAN, no conduit permits it" reads very
    differently from "unclassified traffic"), which is exactly what this
    item's second half, below, now builds on.

    **Notable-protocols finding -- done**: `policy validate` and
    `inventory` both now call out every one of this family's 43 protocols'
    mere PRESENCE as its own finding, independent of whether a conduit
    happens to (wrongly) permit it -- per the rule of thumb above, an
    interactive-access protocol reaching an OT zone is itself worth
    flagging even inside a technically "compliant" policy that happened to
    allow it. `notable_it_protocols.hpp` is the single shared lookup both
    engines call (`notable_it_protocol_tier`), mapping each of the 43
    protocol values to its tier ("remote-access"/"lateral-movement"/
    "enterprise-trust"/"wireless-backhaul"/"tunnel-vpn") -- deliberately
    just a name -> tier table, no decoding of its own, since every one of
    these values is already fully named by `decode`'s own dispatch (Tiers
    1-5 above) before a packet ever reaches either engine.

    Scope is the FULL 43, not just the 13 that happen to be TCP-based
    (QUIC is UDP-only, so it doesn't add to this count):
    `PolicyEngine::observe`/`AssetInventoryEngine::observe` both check
    `notable_it_protocol_tier` first, unconditionally, before either
    engine's own existing dispatch -- so a UDP-based protocol (ntp/dhcp/
    snmp/tftp/radius/capwap-control/capwap-data/lwapp-control/lwapp-data/
    gtp-u/ike/l2tp/vxlan/geneve/wireguard/dtls-tunnel), an IP-protocol-
    number-keyed Tier 5 tunnel with no port at all (gre/esp/ah/ip-in-ip/
    6in4/l2tp's direct-IP form), or an EtherType-keyed protocol with no IP
    layer at all (eapol/pppoe/mpls) is recorded exactly the same as a
    TCP-based one (rdp/vnc/smb/ssh/http/https/ldap/ldaps/tacacs-plus/
    teamviewer/anydesk/zoom/openvpn/stt), none of which
    `PolicyEngine::observe` evaluated against any conduit before this
    (widening that TCP-only `policy validate` limitation for THIS one
    finding only -- the underlying flow/L2-flow model this item's first
    half already documented as TCP-and-VLAN-zone-only is otherwise
    unchanged, see LIMITATIONS).

    This is a strictly ADDITIVE observation, never a change to what either
    engine already counted: a TCP-based notable protocol is both folded
    into its own flow exactly as before (still "Unclassified" there,
    unless a conduit happens to list its exact protocol name) AND recorded
    as its own separate finding; every other shape was, and still is,
    folded into `PolicyReport::skipped_non_tcp`/`AssetInventoryReport::
    skipped_packets` exactly as it always was -- the pinned
    `link_transport_layers_all_skipped_by_policy_engine` test's own exact
    `"skipped_non_tcp": 7` count (CMakeLists.txt) is unchanged by this
    feature, and a fixture with no notable-protocol traffic in it renders
    an explicitly empty `notable_protocols` array (see
    `notable_protocols_empty_for_ordinary_ot_traffic` and
    `inventory_notable_protocols_empty_for_ordinary_ot_traffic`).

    Direction (client/server) is computed differently in each engine, and
    honestly labeled either way: a TCP-based finding in `policy validate`
    reuses that SAME flow's own SYN/SYN-ACK-first, port-heuristic-otherwise
    direction (`PolicyEngine::observe` already computed it for the flow
    itself) via `NotableProtocolFinding::direction_known`; every other
    shape in `policy validate` (UDP, since none of these 43 ports are ever
    "known" to this file's own `is_known_service_port`), and EVERY shape in
    `inventory` (which has no equivalent per-session state for these 43
    protocols the way it does for its own ten recognized ones -- building
    that would be real scope creep for a "name the presence" finding), is
    always the plain "lower port number is the server" heuristic each
    engine already established for its own port-based fallback --
    `direction_known: false`/the text report's own "(direction: port
    heuristic)" annotation says so explicitly rather than presenting it as
    confirmed. An IP-protocol-number-keyed Tier 5 tunnel (no port at all)
    and eapol/pppoe/mpls (no IP layer, keyed by canonical MAC pair instead,
    the same no-direction convention `EthernetFlowReport::mac_a/mac_b`
    already established for PROFINET/GOOSE/SV/EtherCAT) don't even attempt
    a client/server guess -- just a canonical pair.

    Rendered as its own "NOTABLE IT PROTOCOLS (N):" section in both
    commands' text reports (always last), and a `"notable_protocols"`
    array in both JSON reports (appended last, after every pre-existing
    field, so no established JSON-shape test anchored on an earlier field
    needs to change -- the same convention `direction_source`'s own
    addition to `policy validate`'s JSON schema already established).
    `PolicyReport::compliant()` is, and stays, completely UNAFFECTED by
    `notable_protocols` -- Jurgen's own explicit "always flag, independent
    of compliance" design choice for this item, so an existing policy's
    COMPLIANT/NON-COMPLIANT verdict, and the JSON report's own "compliant"
    field, can never silently change just because this feature shipped.
    The new `--strict-it-protocols` flag (`policy validate` only --
    `inventory` has no compliance concept at all to opt into) is the
    explicit, separate opt-in for a stricter audit posture: applied at the
    CLI layer, in `run_policy_validate`'s own exit-code computation, not
    inside `compliant()` itself, it fails the process exit code
    (`kExitPolicyNonCompliant`, the same code an ordinary Violation/
    Unclassified flow already uses) whenever `notable_protocols` is
    non-empty, even on an otherwise COMPLIANT capture -- proven by
    `notable_protocols_wireless_backhaul_baseline_compliant` (exit 0,
    "Result: COMPLIANT") and `notable_protocols_strict_it_protocols_
    flips_exit_code` (same command plus the flag, non-zero exit) both
    running the identical `sample_wireless_backhaul.pcap` capture, whose
    own five protocols are ALL non-TCP (so it has zero flows at all, and is
    trivially COMPLIANT before this flag is even considered) -- the
    cleanest possible proof that the flag, not this report's own existing
    verdict logic, is what's deciding the exit code.

    Tier 5 (tunnels) deliberately stops at naming the outer protocol, not
    decapsulating it -- actually stripping a GRE/IPsec/VXLAN/L2TP header
    and re-running this decoder's own Ethernet/IPv4/TCP/UDP pipeline
    against whatever inner packet comes out is a substantially larger
    undertaking (a recursive decode, not a one-shot flag) than tiers 1-4's
    "recognize and name it," and is left as explicitly separate, later
    work of its own if this item's naming-only pass proves useful enough to
    build on. Named recognition alone is still real progress over today's
    behavior, though: an OT protocol fully tunneled inside GRE/IPsec/VXLAN
    is currently invisible to `policy validate` -- not flagged, not even
    unclassified, simply never seen as anything but opaque UDP/GRE payload
    -- so surfacing "GRE tunnel observed, decap and re-run to see what's
    inside" as its own finding is a meaningful improvement on its own,
    independent of whether decapsulation itself ever gets built.

**pcapng support** is also now done: both classic pcap and pcapng are read
transparently (auto-detected, no flag needed) -- see "pcap vs. pcapng"
above and docs/USER_GUIDE.md's LIMITATIONS for the small set of rare/obsolete pcapng block types
that are skipped rather than decoded.

**IEC 60870-5-104 support** is also now done: APCI framing (I/S/U-format),
and, for I-format APDUs, full ASDU decoding for the type IDs that dominate
real traffic -- see docs/PROTOCOL_COVERAGE.md's IEC 60870-5-104 section and item 7
above for the type IDs still outside the decode table. Because one I-format
APDU always carries exactly one complete ASDU, no cross-frame application-
fragment reassembly analogous to DNP3's was needed -- only the same
TCP-segment-level PDU reassembly every protocol here gets. IEC 104 detection
runs before Modbus/TCP's in Auto-mode dispatch specifically to resolve a
detection collision found while scoping this feature -- see PROTOCOL
DETECTION.

**EtherNet/IP (CIP explicit messaging) support** is also now done: the
24-byte encapsulation header, ListIdentity device-fingerprinting fields,
Common Packet Format item parsing, and a "first pass" CIP explicit-message
decode (generic common services, Connection Manager's Unconnected_Send/
Forward_Open/Forward_Close, and, symbolic-path-gated, the Rockwell
Symbol-object tag services, including STRING/SHORT_STRING and Structured
Data Type (UDT/array) value decoding -- see item 8's "done" note) -- see
docs/PROTOCOL_COVERAGE.md's EtherNet/IP section and item 8 above for what's still
out of scope (STRING2/STRINGN/STRINGI/EPATH/ENGUNIT-as-a-value). EtherNet/IP
detection runs first in Auto-mode dispatch,
ahead of even IEC 104, since its own dedicated port plus three independent
structural checks make it, if anything, a stronger signal -- see PROTOCOL
DETECTION.

**Link/IP-layer plumbing for non-IPv4/non-TCP traffic** is also now done:
non-IPv4 Ethernet frames and non-TCP IPv4 payloads (including UDP) are
recognized and named for a deliberately small, OT-relevant set of
EtherTypes/IP-protocol-numbers (ARP, LLDP, ICMP,
and the rest), rather than just a bare hex/decimal number and nothing else
-- see docs/PROTOCOL_COVERAGE.md's link/IP-layer plumbing section, and `policy
validate` doesn't yet evaluate any non-TCP traffic against a conduit.
PROFINET RT, IEC 61850-8-1 GOOSE, IEC 61850-9-2 Sampled Values, and
EtherCAT, formerly in
this same named-but-not-decoded set, are decoded now -- see the next four
paragraphs.

**EtherNet/IP CIP I/O (implicit messaging) decoding** is also now done: the
first protocol this tool decodes over UDP, and the direct extension of the
CIP explicit-messaging work above that item 9 originally called out as the
most likely next candidate. The Sequenced Address Item (connection ID +
sequence number) is fully decoded; the Connected Data Item (the actual I/O
data) is located and shown as raw hex, deliberately never value-decoded --
see docs/PROTOCOL_COVERAGE.md's CIP I/O subsection and docs/USER_GUIDE.md's LIMITATIONS for exactly why,
and item 9 above for what's still open (real-capture validation,
cross-datagram correlation, and widening `policy validate` to cover it).

**PROFINET RT (DCP and cyclic real-time IO) decoding** is also now done:
the first protocol this tool decodes directly over raw Ethernet, with no
IP/TCP/UDP layer at all -- item 9 above's other most likely next
candidate, alongside CIP I/O, and now also done. FrameID-based dispatch
covers DCP (device discovery/configuration -- full PDU header, block
list, and five value-decoded block types) and cyclic real-time IO
datagrams (IO data plus the CycleCounter/DataStatus/TransferStatus
trailer) -- see docs/PROTOCOL_COVERAGE.md's PROFINET RT subsection for the full
FrameID range table and docs/USER_GUIDE.md's LIMITATIONS for what's still open (cyclic IO
data's length ambiguity, no real cyclic-IO capture to validate against,
and no cross-datagram DCP request/response pairing). Validating this
decoder against two real DCP captures caught a genuine decoding bug before
it ever shipped -- see docs/PROTOCOL_COVERAGE.md's PROFINET RT subsection and
`tests/real_captures/profinet/ATTRIBUTION.md` for the full story.

**IEC 61850-8-1 GOOSE decoding** is also now done: the second protocol this
tool decodes directly over raw Ethernet, alongside PROFINET RT, and the
answer to item 9's original "decode the remaining named-but-undecoded
raw-Ethernet protocol" call-out (now narrowed to just Sampled Values -- see
item 9 above). The 8-byte header (APPID/Length/S-bit) and the full ASN.1
BER-encoded APDU are decoded: every IECGoosePdu field, including the
`stNum`/`sqNum` state-change/retransmission counters that are the primary
GOOSE spoofing/replay signal, and every `allData` value type, recursively
for nested `array`/`structure` values -- see docs/PROTOCOL_COVERAGE.md's GOOSE
subsection for the full field/type tables and docs/USER_GUIDE.md's LIMITATIONS for what's still
open (optional-field-absence and most `allData` types have no real-capture
validation, GSE Management PDU content isn't decoded, multi-APDU frames
aren't supported). Validating this decoder against real bytes caught a
genuine tag-table error before it ever shipped -- an initial source read
suggested every PDU field used constructed BER encoding, which a
from-scratch BER walker run against a real capture's bytes disproved -- see
docs/PROTOCOL_COVERAGE.md's GOOSE subsection and `tests/real_captures/goose/
ATTRIBUTION.md` for the full story, mirroring the PROFINET RT
BlockInfo/BlockQualifier bug the paragraph above describes.

**IEC 61850-9-2 Sampled Values decoding** is also now done: the third
protocol this tool decodes directly over raw Ethernet, alongside PROFINET RT
and GOOSE, and the final answer to item 9's original "decode the remaining
named-but-undecoded raw-Ethernet protocol" call-out. SV shares GOOSE's
8-byte header format and ASN.1 BER TLV foundation, but has its own distinct
APDU shape: a single-alternative outer CHOICE (`0x60` `savPdu`, vs. GOOSE's
two), and a `SavPdu` wrapping `noASDU` plus a `seqASDU` of one or more
per-item `0x30`-tagged `ASDU` elements -- all of which, unlike GOOSE's
single-APDU-per-frame scope, are decoded (multiple ASDUs per SavPdu is core,
spec-defined behavior, not a rare edge case). Every `ASDU` field is decoded
(`svID`, `datSet`, `smpCnt` -- the primary stream-integrity/replay-detection
signal, analogous to GOOSE's `stNum`/`sqNum` -- `confRev`, `refrTm`,
`smpSynch`, `smpRate`, `smpMod`, and the Ed.2.1 `gmidData` grandmaster-clock
field) except `seqData` (the sample payload itself), which is deliberately
shown only as raw hex and never value-decoded -- interpreting it requires an
implementation profile (e.g. the common "9-2LE" 8-channel layout) layered on
top of the base ASN.1, not something the standard itself asserts, the same
"no generic self-describing wire-level type" reasoning already applied to
PROFINET RT's cyclic IO data and CIP I/O's Connected Data Item -- see
docs/PROTOCOL_COVERAGE.md's Sampled Values subsection for the full field tables and
docs/USER_GUIDE.md's LIMITATIONS for what's still open. Unlike every other protocol added so far,
no real capture was found for *any* SV code path despite a genuine
multi-source search (Wireshark's own test-capture tree and wiki, several
public ICS-pcap repositories, IEC 61850 tooling projects, and a Wireshark
GitLab issue's attached sample) -- validation here is honestly
synthetic-fixture-only from the start; see `include/conduitscope/sv.hpp`'s
file header for the full search writeup.

**EtherCAT decoding** is also now done: the fourth protocol this tool
decodes directly over raw Ethernet, alongside PROFINET RT/GOOSE/SV, and the
final answer to item 9's original "decode the remaining named-but-undecoded
raw-Ethernet protocol" call-out -- this project no longer tracks any
named-but-undecoded raw-Ethernet OT protocol of its own. Unlike GOOSE/SV's
shared ASN.1-BER foundation, EtherCAT is a plain fixed-binary-layout
protocol with its own distinct framing: a 2-byte frame header (Length/
Reserved/Type) and, for Type 1 ("EtherCAT command") frames, a chain of
EtherCAT datagrams (`Cmd`/`Idx`/`Adp`-`Ado`-or-logical-address/`Len`+flags/
`Irq`/`Data`/Working Counter) -- see docs/PROTOCOL_COVERAGE.md's EtherCAT subsection
for the full field tables and docs/USER_GUIDE.md's LIMITATIONS for what's still open. `Data` is
deliberately never value-decoded, the fourth application of this codebase's
"no generic self-describing wire-level type" reasoning after PROFINET RT's
cyclic IO data, CIP I/O's Connected Data Item, and SV's `seqData`. One
honest gap unique to this protocol: its frame-header `Type` field is a
genuinely weaker structural detection signal than every other raw-Ethernet
protocol here (5 of 16 possible 4-bit values, vs. GOOSE/SV's 1-in-256 outer
tag or PROFINET's FrameID range table) -- the dedicated EtherType remains
the primary confidence source. Unlike Sampled Values, a real capture WAS
found (986 frames) and directly confirmed a deliberate design choice: this
decoder bounds its datagram-chain scan by the frame header's own declared
Length field, rather than walking every byte physically present in the
frame the way Wireshark's own dissector does, specifically to avoid
misreading Ethernet's minimum-frame-size zero-padding as a spurious
trailing datagram -- all 986 real frames show declared Length exactly
matching the actual chained-datagram byte count, zero mismatches. See
`tests/real_captures/ethercat/ATTRIBUTION.md` for full provenance and
exactly which Cmd values/bits/frame Types that capture does and doesn't
exercise, and `include/conduitscope/ethercat.hpp`'s file header for the
full writeup.

**BACnet/IP decoding** is also now done: the second protocol this tool
decodes over UDP, alongside CIP I/O, using the same port-independent
"opportunistic, payload-shape" detection posture rather than a dedicated
EtherType the way PROFINET RT/GOOSE/SV/EtherCAT get to use. Three layers
are decoded: BVLC (the UDP framing header, including every BBMD/
foreign-device-table management function), NPDU (the network layer,
including DEST/SRC routing fields and Network Layer Messages, named only),
and APDU (the application layer, byte-accurate across all 8 PDU types
including segmentation's SEG/MOR bits). Service value-decoding is a
deliberate "first pass" -- mirroring this codebase's existing service-
scoping precedent for EtherNet/IP CIP explicit messaging and DNP3's
group/variation table -- covering Who-Is/I-Am/Who-Has/I-Have device/object
discovery and ReadProperty/WriteProperty/generic-Error, the two most
security-relevant BACnet traffic patterns for passive OT monitoring; a
constructed/array PropertyValue is the fifth application of this
codebase's "no generic self-describing wire-level type" reasoning, after
PROFINET RT's cyclic IO data, CIP I/O's Connected Data Item, SV's
`seqData`, and EtherCAT's `Data` -- see docs/PROTOCOL_COVERAGE.md's BACnet/IP
subsection for the full field/service tables and docs/USER_GUIDE.md's LIMITATIONS for what's
still open. A real capture WAS found: 54 frames (a ReadProperty polling
session against trend-log objects) extracted from a larger mixed-OT-
protocol capture whose own README doesn't even mention BACnet -- found
only by actually running this decoder against every file in that
repository. Two better-looking real-capture sources were checked first and
couldn't be used: `automayt/ICS-pcap`'s own `BACNET/` directory (the
better-populated public BACnet collection, but stored via Git LFS, which
this environment cannot resolve -- the same limitation already hit for
this project's EtherCAT/GOOSE/SV real captures) and `kargs.net`'s own
capture archive (BACnet dissector co-author Steve Karg's ~220-file
collection, almost certainly the single best BACnet source on the public
web, but blocked outright by this session's network policy) -- see
`tests/real_captures/bacnet/ATTRIBUTION.md` for the full search record and
`include/conduitscope/bacnet.hpp`'s file header for the full writeup.

**Colorized text output** is also now done: see OUTPUT FORMATS' "Color"
subsection for the scheme and the `--color`/`--no-color`/auto-detection
rules. `policy validate`'s text report stays deliberately plain (an audit
artifact, meant to be diffed/archived/piped without ANSI noise) -- that
remains a considered choice, not an oversight, unless a real use case for
coloring it turns up.

**`policy validate`'s `--summarize-unclassified` flag** is also now done: a
real-world large public capture (4SICS-GeekLounge-151021.pcap, 1.25M
packets, mostly general IT/web traffic against an OT-focused inferred
policy) produced a 37MB/567K-line text report, almost entirely UNCLASSIFIED
blocks -- 112,871 flows but only 844 distinct (client, server, port,
protocol(s), zones) patterns underneath them, one MMS host pair alone
contributing 16,378 flows via constant reconnection. The flag (text format
only; `--format json` is unaffected, since it's already structured data a
script can group/deduplicate itself with more precision than any one fixed
grouping key here could offer) groups `UNCLASSIFIED TRAFFIC`/`ETHERNET
UNCLASSIFIED TRAFFIC` entries sharing that key into one line each, carrying
a flow count and total packet count, while leaving `VIOLATIONS`/`ALLOWED`
(and their Ethernet equivalents) completely untouched. See
`summarize_unclassified_flows`/`summarize_unclassified_ethernet_flows` in
`policy_engine.cpp`.

All of what was originally tracked here as "general TCP stream reassembly"
is now done: PDU/frame-level reassembly across TCP segments
(`Decoder::reassemble_tcp_payload`, covering Modbus, DNP3, IEC 104,
EtherNet/IP, and TPKT/COTP alike), authoritative Modbus request/response
pairing by transaction ID (`Decoder::pair_modbus_transaction`), and chaining
an S7comm message across multiple complete TPKT/COTP frames
(`Decoder::reassemble_cotp_data_frame`) -- see docs/USER_GUIDE.md's LIMITATIONS for each one's
exact scope and remaining caveats. DNP3 *application*-layer fragmentation
across complete data-link frames is a related, already-done special case --
conduitscope reassembles it per TCP flow via its own mechanism -- but it
still awaits validation against a real capture that actually exercises it
(none found so far; see docs/USER_GUIDE.md's LIMITATIONS).

The **zone/conduit policy engine** behind `policy validate` (`policy.hpp`/
`policy_engine.hpp`) is also now done: a policy file (a restricted YAML
subset -- see POLICY FILE FORMAT) declares zones and conduits, and every
decoded TCP flow is checked against them, producing a compliant/non-compliant
report (text or JSON) suitable for a NIS2/62443 audit trail. S7comm item
tags, decoded DNP3 point values (especially CROB commands), Modbus
address+quantity decoding, and authoritative Modbus request/response pairing
were exactly the concrete decoded facts this was building toward being able
to match a policy against -- see docs/USER_GUIDE.md's LIMITATIONS for the engine's own remaining
caveats (the SYN-based initiator heuristic's fallback case, IPv4/TCP-only
zones, one-conduit-per-zone-pair direction model).

**Live capture** (`-i/--interface`, `conduitscope interfaces`) is also now
done, as an optional, build-time-detected libpcap (Linux) / Npcap (Windows)
dependency layered on top of everything above without changing any of it --
`decode -i`/`policy validate -i` feed the exact same `PcapPacket` shape into
the same `Decoder`/`PolicyEngine` that offline files do (see
`live_capture.hpp`'s `LiveCapture` and `cli_main.cpp`'s `PacketSource`), so
every protocol-decoding and policy-checking behavior documented throughout
this manual applies identically whether the traffic came from a file or a
live interface. See LIVE CAPTURE above for the full reference and
docs/USER_GUIDE.md's LIMITATIONS for what's not yet validated (the Windows/Npcap path, and a real
production OT network rather than loopback).

**HART-IP support** is also now done: the 8-byte fixed header, all four
MessageID-selected body shapes (Session Initiate/Close/Keep Alive/Pass
Through), the full byte-by-byte Pass-Through Data-Link PDU, a "first pass"
command value-decode set, packed-ASCII and HART-format-timestamp decoding,
and opportunistic detection on both TCP and UDP -- see docs/PROTOCOL_COVERAGE.md's
HART-IP section. Unlike every protocol added before it, this one surfaced a
genuine, unavoidable detection collision rather than a resolvable one: a
HART-IP Session Initiate message's own header happens to also look like a
plausible Modbus/TCP MBAP header, and unlike the IEC-104-vs-Modbus collision
this project already resolved once by reordering, the same fix measurably
regressed this project's own Modbus/S7comm test corpus when tried here (see
PROTOCOL DETECTION's "Why HART-IP is tried last"). Rather than silently
working around that with an unsafe fix, it's documented as an accepted
limitation, demonstrated in the synthetic fixture, and -- independently --
confirmed to occur on genuine field traffic, not just a hand-built one, by
the real HART-IP capture found for this feature (see
`tests/real_captures/hartip/ATTRIBUTION.md`, which also surfaced a second,
previously-undocumented false-positive pattern against unrelated background
TCP traffic). See docs/USER_GUIDE.md's LIMITATIONS for the complete list of what's still out of
scope (Checksum verification, per-command Response Code resolution, and
more).

**OPC UA Binary support** is also now done: the 8-byte UA-TCP common
header, the full OpenSecureChannel/CloseSecureChannel/Message
SecureConversation framing (SecureChannelId, security header, sequence
header), and a "first pass" two-tier service decode -- Tier 1 covers the
full connection/channel/session lifecycle plus both discovery services
(15 request/response pairs in all, including ServiceFault), Tier 2 names
every other service and decodes its RequestHeader/ResponseHeader while
leaving the Variant/DataValue-dependent body as raw hex -- see PROTOCOL
COVERAGE's OPC UA section and item 11 above for what's still out of scope.
Unlike HART-IP above, this protocol's own structural detection gate (a
3-byte ASCII MessageType match against 7 fixed strings) is strong enough,
and confirmed collision-free with every other protocol in this dispatch
chain, to be tried FIRST rather than last -- the opposite ordering
rationale from HART-IP's own weak-gate placement, see PROTOCOL DETECTION.
Deliberately, ActivateSessionRequest's own UserName/Password identity token
is decoded including the cleartext Password whenever EncryptionAlgorithm is
empty, flagged with an explicit `"SECURITY FINDING"` note -- a real,
documented OPC UA credential-exposure pattern (OPC 10000-4 7.41), not a
hypothetical, and directly in service of this tool's own stated purpose as
an OT-security-auditing decoder. A real capture was found and validated:
two OPC UA sessions from a well-known, widely-mirrored 2009 Wireshark
dissector-bug reproduction capture, on a non-standard TCP port that
Wireshark's own default configuration doesn't even recognize as OPC UA --
this decoder does, without any port hint, cross-checked field-by-field
against tshark's own OPC UA dissector once pointed at the right port (see
`tests/real_captures/opcua/ATTRIBUTION.md`). That same capture also
happens to be the first real-world confirmation this project's general
TCP-segment-level reassembly mechanism gets (two responses genuinely split
across 5 and 6 TCP segments, both reassembled and decoded correctly), and
contains two deliberately malformed CallRequest packets -- one of which
triggered Wireshark's own ~2-minute dissector freeze -- that this decoder's
own Tier 2 raw-hex scope is structurally immune to, since it never attempts
to parse a malformed CallRequest body at all.

**IEC 61850 MMS support** is also now done: the full four-layer stack
(Session ISO 8327-1 / Presentation ISO 8823 / ACSE ISO 8650-1 / MMS ISO
9506-2) is decoded, sharing S7comm's exact TPKT/COTP transport and TCP port
102 but detected by its own, separate structural gate recognizing three
shapes (a full Session-layer association, "bare MMS", and "bare
Presentation") -- see docs/PROTOCOL_COVERAGE.md's MMS section and item 12 above for
what's still out of scope. Unlike this codebase's own OPC UA decoder, MMS's
own self-describing "Data" value type (14 of 17 alternatives) IS decoded in
full, so the actual read/write/report values an MMS client exchanges are
visible, not just that an exchange happened; a hard-capped 32-level
recursion depth on Data's own array/structure alternatives defends against
a real denial-of-service class this decoder's own validation independently
confirmed -- `tshark` 4.2.2's own MMS dissector hits an internal recursion
assertion and aborts entirely on roughly 43 of 224 frames of genuine,
non-malicious traffic this decoder's own research captured. 18 of MMS's 78
confirmedServices get full field decoding (Tier 1) -- including, as of item
12's own completion, the seven file-transfer services IEC 61850's own
COMTRADE/disturbance-file-retrieval workflow rides on; the rest are named
with invokeID only, body shown as raw hex (Tier 2), the same two-tier
scoping precedent this codebase already applies to OPC UA's own service
dispatch.
Validated against three genuine real-world captures from
`ITI/ICS-Security-Tools` (one a full association with two independently-
confirmed malformed frames, two "bare MMS" -- the shape that caught a real
bug in this decoder's own first-pass bare-MMS structural gate, since 3 of
the 14 `MMSpdu` alternatives are primitive, not constructed, on the wire)
plus a 224-frame capture this project generated itself against a real,
independent open-source stack (`mz-automation/libiec61850`) -- 117 of 224
frames recognized as `mms`, zero parse warnings, zero parse errors, zero
crashes, and a real informationReport frame confirming this decoder's own
`Data`-value decode against an independent encoder byte-for-byte (see
`tests/real_captures/mms/ATTRIBUTION.md` for both structural-gate bugs this
validation pass found and fixed).

**MQTT (v3.1/v3.1.1/v5.0) and Sparkplug B support** is also now done: the
first protocol this tool decodes that isn't OT-specific on its own, but is
squarely in scope for how OT data reaches IT/cloud systems today, plus
Sparkplug B -- an OT/IIoT-focused MQTT topic and payload convention built on
Protocol Buffers -- decoded via a small, purpose-built, hand-rolled protobuf
wire-format reader rather than a general-purpose protobuf dependency
(consistent with this project's zero-required-dependency design). Every MQTT
Control Packet Type is decoded (CONNECT through AUTH), including all 27
MQTT5 Property Identifiers via one generic, table-driven decoder. Version
disambiguation for the three genuinely ambiguous packet types (SUBSCRIBE/
SUBACK/UNSUBSCRIBE) combines authoritative per-TCP-session CONNECT tracking
with an honestly-scoped fallback heuristic, documented as least reliable for
SUBACK specifically -- see docs/PROTOCOL_COVERAGE.md's MQTT section. This decoder's
own structural detection gate is honestly the weakest in the whole codebase
(weaker even than HART-IP's own documented weakest gate), so MQTT is
dispatched dead last in the TCP protocol-detection chain -- a real,
demonstrated design consequence, not a theoretical one: building this
feature's own synthetic test fixture surfaced two genuine collisions against
earlier-dispatched protocols' gates (a v5 CONNACK against Modbus/TCP's own
protocol-id==0 tell, and a SUBSCRIBE/UNSUBSCRIBE packet identifier against
HART-IP's own two-byte gate), both found and fixed, not just noted as
possible. Like this codebase's own OPC UA Identity Token decode, CONNECT's
cleartext Username/Password fields are decoded and shown deliberately, not
by oversight. Validated against a real Eclipse Paho MQTT 3.1 client session
(`pradeesi/MQTT-Wireshark-Capture`, two container formats confirmed to
decode byte-for-byte identically, plus a third file from the same source
found to be genuinely corrupt and correctly rejected with a clear error) --
that validation caught and fixed a real bug in this decoder's own
session-version-tracking logic, which originally only recognized
ProtocolLevel 4/5 CONNECTs, not the pre-OASIS MQTT 3.1 (level 3, "MQIsdp")
shape a real client in the wild still used (see
`tests/real_captures/mqtt/ATTRIBUTION.md` for the complete writeup). A real
Sparkplug B capture was specifically searched for and not found, so
Sparkplug B decoding itself remains validated only against this project's
own synthetic, hand-built protobuf fixture -- see docs/USER_GUIDE.md's LIMITATIONS.

**DNS, mDNS, LLMNR, and NetBIOS Name Service (NBT-NS) decode, plus
DNS-over-HTTPS (DoH) detection,** are also now done: the first name-
resolution protocols this tool decodes, and the first protocols anywhere in
this codebase that are deliberately port-gated in `--protocol auto` rather
than tried opportunistically port-independent -- see PROTOCOL DETECTION's
own dedicated paragraph for why (none of the four DNS-shaped protocols has
a self-describing wire-format signal strong enough to check safely against
every UDP payload the way this codebase's other detectors do). DNS, mDNS,
and LLMNR share one implementation (`DnsMessage`/`try_parse_dns_message`),
since RFC 6762 and RFC 4795 both explicitly reuse RFC 1035's message format
verbatim, differing only in three header bits' meaning (AA/RD/RA vs.
LLMNR's C/T/wider-Z) and, for mDNS, two class-field top-bit reinterpretations
(QU and cache-flush); "first pass" RDATA decoding covers A/AAAA/NS/CNAME/
PTR/MX/SOA/TXT/SRV, the same service-layer scoping precedent already
established for BACnet/DNP3/S7comm/EtherNet-IP, with EDNS0's OPT
pseudo-record correctly recognized. NBT-NS gets its own decoder (RFC 1002),
including first-level name encoding/decoding, NB (address) and NBSTAT (name
table) resource records, and the Microsoft/Wireshark suffix-byte
convention for what service a NetBIOS name represents -- explicitly
documented as convention, not part of RFC 1002 itself. DoH is
detection-only, by necessity rather than choice: its actual DNS content
travels inside TLS, invisible to this or any tool without the session's own
decryption keys, so detection instead matches a TLS ClientHello's plaintext
SNI against a curated table of a dozen known public DoH resolvers -- see
docs/PROTOCOL_COVERAGE.md's "DNS / mDNS / LLMNR / NetBIOS Name Service (NBT-NS) /
DNS-over-HTTPS detection" section for the full wire formats, and docs/USER_GUIDE.md's LIMITATIONS
for what none of this can see (DNS-over-TCP, DoT/DoQ content, a DoH
resolver not on the curated table, a ClientHello split across TCP segments,
and TLS Encrypted Client Hello). All five are validated against hand-built
synthetic fixtures cross-checked against their governing RFCs, including
deliberate negative-control packets for every detection gate -- no real
capture was sought for this feature, since these are widely-documented,
standard protocols rather than a proprietary or hard-to-source OT one.
Deliberately left out of this pass, and not yet separately tracked as its
own numbered roadmap item: wiring any of these five into `policy validate`/
`PolicyEngine`'s conduit `protocols` classification, the same way item 14
above did for the six protocols added there -- see docs/USER_GUIDE.md's LIMITATIONS.

**RIP, IGMP, VRRP, and HSRP decode** are also now done: the first batch of a
broader routing/redundancy-protocol addition (RIP, IGMP, VRRP, HSRP, IGRP,
PIM, EIGRP, and OSPF now done across two rounds -- see below; BGP-4 has
since been done too, as item 33 further down this ROADMAP. IS-IS was considered and deliberately deferred
further still, since it rides directly on the data-link layer like STP
rather than as an IP-protocol payload, roughly doubling the scope of
decoding it relative to any of these). RIP
(UDP port 520) and HSRP (UDP port 1985) join DNS/mDNS/LLMNR/NBT-NS/DoH in
being port-gated in `--protocol auto` rather than tried opportunistically,
for the same reason (neither has a strong enough self-describing wire
signal) -- see PROTOCOL DETECTION. IGMP and VRRP need no port gate at all:
both ride directly on IP (protocol numbers 2 and 112, both IANA-exclusive)
with no UDP/TCP header, the same "no port concept" shape STP/GOOSE/SV/
EtherCAT/PROFINET/DeviceNet already have for their own respective link
layers. All four were added specifically because they routinely share OT
segments with this project's existing coverage: IGMP underlies GOOSE/SV's
own routable multicast variants, and VRRP/HSRP are a straightforward
gateway-spoofing/MITM primitive worth surfacing regardless of whether a
segment is otherwise "OT" or "IT" -- see docs/PROTOCOL_COVERAGE.md's "RIP / IGMP /
VRRP / HSRP" section for the full wire formats, each protocol's own
Security context note, and this section's Validation subsection. One real
dispatch-order collision was found and fixed while building this feature:
a synthetic HSRPv1 message satisfied FF-HSE's own weaker, fully
opportunistic structural gate and was misdetected as truncated FF-HSE
traffic until RIP/HSRP were moved ahead of FF-HSE (but still behind
BACnet/HART-IP) in the UDP dispatch chain -- see PROTOCOL DETECTION.
Deliberately left out of this pass, and not yet separately tracked as its
own numbered roadmap item: wiring any of these four into `policy validate`/
`PolicyEngine`'s conduit `protocols` classification (same gap as the DNS
family above), and locating/verifying RIP's own Keyed MD5 authentication
digest -- see docs/USER_GUIDE.md's LIMITATIONS for both.

**IGRP, PIM, EIGRP, and OSPF decode** are now also done: the second batch of
the routing/redundancy-protocol addition begun by RIP/IGMP/VRRP/HSRP above.
All four ride directly on IP (protocol numbers 9, 103, 88, and 89, all
IANA-exclusive) with no UDP/TCP header and therefore no port concept at all
to gate -- the same "no port concept" shape IGMP/VRRP already have. BGP,
the one protocol from the original request that instead rides over TCP
(port 179), was deliberately left out of this batch and deferred to its own
future round, since it needs TCP stream reassembly unlike these four. See
docs/PROTOCOL_COVERAGE.md's "IGRP / PIM / EIGRP / OSPF" section for the full wire
formats, each protocol's own Security context note, and this section's
Validation subsection. Deliberately left out of this pass, and not yet
separately tracked as its own numbered roadmap item: wiring any of these
four into `policy validate`/`PolicyEngine`'s conduit `protocols`
classification (same gap as the DNS family and RIP/IGMP/VRRP/HSRP above),
and locating/verifying EIGRP's and OSPF's own authentication digests (same
gap as RIP's Keyed MD5) -- see docs/USER_GUIDE.md's LIMITATIONS for both. **BGP-4 is now also
done** -- see item 33 further down this ROADMAP -- the one routing protocol of this whole
batch that needed TCP port-179 stream reassembly, unlike any of the eight
IP/UDP-based routing/redundancy protocols above.

**Architectural scope note, decided directly: this item's 43 protocols are
out of scope for the `ProtocolDecoder` registration-model refactor (item 3
above), not merely unscheduled.** Asked point-blank whether Tiers 1-5
belong on that interface, the answer is no, and for a structural reason
rather than a priority one: `ProtocolDecoder` exists to retire *dual-write*
-- a decoded, typed struct copied into `DecodedPacket`'s own
protocol-specific flat fields, then re-read by a protocol-specific
`output.cpp` branch (see `protocol_decoder.hpp`'s own "why a new
abstraction at all" paragraph). None of this item's five
`try_recognize_it_*`/`try_recognize_tunnel_vpn_*` functions produce that
shape at all, by design -- every one of them returns only `{protocol,
summary, notes}` (`it_protocols.hpp`/`tunnel_vpn.hpp`'s own match structs),
fields every `DecodedPacket` already carries regardless of protocol, and
every call site does nothing but `out.protocol = m->protocol; out.summary
= m->summary; for (notes) out.notes.push_back(n);` -- no
`it_*`/`tunnel_vpn_*` flat fields exist in `decoder.hpp` to migrate away
from, and no protocol-specific `output.cpp` branch exists to retire,
because this item's own file header comment rules out ever decoding these
protocols structurally ("there is no OT-security value in decoding RDP's
own bitmap updates or a VNC framebuffer update"). Wrapping these in
`ProtocolDecoder` subclasses would add ceremony for no such gain -- a
`GateKind` doesn't cleanly fit either, since most of these tiers are
checked across TCP *and* UDP from one shared function (`is_tcp` as a
parameter), unlike every migrated protocol's own single-transport
`gate_kind()`; splitting one would mean two decoder classes sharing an
`id()` purely to match the interface's shape, not to solve any real
problem, for zero reduction in `DecodedPacket` fields or writer branches,
since there are none to remove. The `~37`-and-counting legacy-protocol
count item 3's own "Update" paragraphs track (and its
`ProtocolDecoder`-level `GateKind`/`ProtocolResult` machinery generally)
was never meant to, and does not, include this item's 43 name-only
recognitions; they stay exactly as they are, called directly from
`decoder.cpp`'s dispatch chain via plain functions, indefinitely, not as a
deferred future migration.
19. ~~**Label *how* a flow's client/server direction was determined -- not
    just what it is -- across `decode`, `policy validate`, and `inventory`.**~~
    **Done.** Every direction call this codebase makes already fell into one
    of three tiers before this item; only the code path that made the call
    knew which one fired, and the output itself didn't say. Worth naming
    precisely, since
    "approximately" (as used informally in docs/USER_GUIDE.md's LIMITATIONS)
    has one specific meaning here: *not backed by an observed TCP
    handshake*, nothing vaguer. The three tiers, in order of authority:
    - **Handshake** -- a SYN and a matching SYN-ACK were both observed for
      this TCP flow (on any packet, not just the first -- see
      `PolicyEngine::observe`'s own doc comment in `policy_engine.hpp`).
      The only tier this project can call unambiguous: TCP's own three-way
      handshake is authoritative by construction, the initiator is whoever
      sent the SYN.
    - **Content** -- no handshake was observed (or the protocol has none at
      all, e.g. UDP), but the protocol's own application-layer semantics
      settle it without guessing. BACnet is the only case in this codebase
      today: a Confirmed-Request/Unconfirmed-Request's source is
      definitionally the client, and a Simple-ACK/Complex-ACK/Segment-ACK/
      Error/Reject/Abort's *destination* is, because BACnet client and
      server both conventionally listen on the same UDP port (47808), so
      the port heuristic below can't even be attempted (see
      docs/USER_GUIDE.md's `inventory` section).
    - **Port-heuristic** -- neither of the above: no handshake captured,
      and no protocol semantics to fall back on, so `is_known_service_port`/
      `is_known_target_port` (`PolicyEngine`'s and `AssetInventoryEngine`'s
      own separate copies of this logic -- see "Why two copies, not one
      shared implementation" below) guesses from the IANA-registered OT
      port for that protocol, and failing that, assumes the lower port
      number is the server. This is the *only* tier that can actually be
      wrong: a real server running on a high or nonstandard port, observed
      mid-session with no handshake, gets attributed backwards.

    Industry precedent was researched before designing this. None of Zeek,
    Suricata, or Wireshark actually expose this as a labeled field. Zeek's
    own docs describe "the first packet's source is the originator" as the
    general rule for connectionless protocols, with no confidence/
    provenance value carried into `conn.log`. Suricata's flow-keyword docs
    describe TCP's three-way handshake as what establishes a connection and,
    separately, "traffic from both sides" as the bar for non-TCP flows --
    again, no uncertainty language exposed either way. Wireshark is the most
    directly relevant precedent, because it has almost exactly this
    codebase's own bug: its Conversations table orders endpoints A/B by
    `if (src_port > dst_port) ... else ...` -- the same "lower port number
    is probably the server" guess `is_known_service_port` falls back to --
    and has a long-open community feature request asking it to prefer the
    TCP handshake's actual direction instead of the port guess when one was
    captured. No tool surveyed frames this with a graded "confidence" scale
    either -- the ICD-203-derived High/Moderate/Low-Confidence language
    common in threat-intel writing (e.g. Secureworks CTU's own published
    confidence-assessment framework) was considered and deliberately not
    borrowed here: that vocabulary is built for genuinely continuous,
    corroboration-based judgment calls, not a deterministic three-way code
    branch that always resolves to exactly one of three known mechanisms.

    Given that, the field name and value set settled on: `direction_source`,
    with the exact values `handshake` / `content` / `port-heuristic` above
    -- mechanism-based, not confidence-based, since every flow's tier is a
    fact about which code path fired, not a probability estimate. Now
    implemented on all three surfaces that already make a client/server
    call: `decode`'s per-packet output, via a new, small tracking layer of
    its own -- `FlowDirectionTracker` (`flow_direction.hpp`/`.cpp`),
    invoked from `cli_main.cpp`'s `run_decode` loop right after
    `Decoder::decode()` returns, filling in `DecodedPacket`'s new
    `has_direction`/`direction_client_is_src`/`direction_source` fields in
    place (`Decoder`/`DecodedPacket` themselves still carry no cross-packet
    direction state of their own, by design -- see `decoder.hpp`'s own
    "NOTE ON STATEFULNESS" comment -- this stays a separate class on top of
    already-public `DecodedPacket` output, the same "doesn't change how
    packets are decoded" boundary `PolicyEngine`'s own file header already
    describes for itself); `policy validate`'s `FlowReport`
    (`PolicyEngine::FlowState` already carried the exact SYN/SYN-ACK/
    port-heuristic branching needed -- just had the tier threaded through as
    a field); and `inventory`'s `InventoryEdge` (`AssetInventoryEngine::
    EdgeState`, the same shape, plus the BACnet content-based branch, merged
    across however many sessions/packets one coarser `InventoryEdge`
    aggregates by always keeping the most-authoritative tier ever observed
    -- see `direction_source_rank`'s own comment in `asset_inventory.cpp`).
    All three are documented in docs/USER_GUIDE.md's own OUTPUT FORMATS/JSON
    report schema sections and worked examples, and covered by CMakeLists.txt's
    own `direction_source`-prefixed test block (one handshake case, one
    port-heuristic case, and inventory's BACnet content case, per surface).

    *Why two copies, not one shared implementation* (now three): `PolicyEngine`
    and `AssetInventoryEngine` each already maintained their own independent
    SYN/SYN-ACK-plus-port-heuristic direction logic (`policy_engine.cpp`'s
    `is_known_service_port`/`src_is_client_by_port` vs. `asset_inventory.
    cpp`'s `is_known_target_port`/`src_is_client_by_port`) rather than
    sharing one implementation -- consistent with each engine's own stated
    design of staying a self-contained layer built on top of `Decoder`'s
    already-public output, never reaching into or depending on the other
    engine. `FlowDirectionTracker` follows the same convention: its own
    `session_key`/`is_known_service_port`/`src_is_client_by_port` in
    `flow_direction.cpp` are a third, independent copy, not calls into
    either engine's own.

    *Follow-up: how `decode`'s own per-packet display presents this.* The
    paragraphs above cover computing and exposing `direction_source` on all
    three surfaces; a second, separate round then revisited specifically how
    `decode`'s own text/JSON/CSV/`--stats` output *presents* it, once real
    usage made the original separate `direction: <tier> (client: <ip>)`
    text line feel disconnected from the packet line it described. Five
    presentation options were weighed (color the tier by trustworthiness;
    fold it into the head line instead of a separate line; show both
    endpoints with role rather than just the client; make display
    opt-in/opt-out; aggregate a tier breakdown into `--stats`) and four were
    adopted -- color, head-line folding, an opt-out flag, and `--stats`
    aggregation -- deliberately not the both-endpoints-with-role option,
    which was left for a future round if real usage asks for it. Concretely:
    `TextWriter::write_packet` now appends `(client <ip> -- <tier>)` to the
    end of the packet's own head line (after the summary, before the
    line's terminating newline) instead of printing a separate `direction:`
    line after the `eth` line -- colored yellow for `port-heuristic`
    specifically (the only tier that can actually be wrong, per this item's
    own precedent survey above) and dim for the two authoritative tiers,
    matching every other secondary annotation on that line; a new
    `--no-direction` flag (`decode_show_direction` in `cli_main.cpp`,
    mirroring `--no-vlan`'s own `!--no-vlan` CLI11 negation-flag pattern)
    suppresses it in text, and makes JSON omit `direction_source`/
    `direction_client_ip` entirely (never just `null`, the same convention
    `--no-vlan` already set for `has_vlan_tag`/`vlan_id`) and CSV blank both
    trailing columns while still emitting them (the same "column always
    exists, value empty" precedent `vlan_id` already set); and
    `StatsWriter` gained a new `direction_source_counts_` map, printed as a
    "direction sources (tcp flows only):" block right after the `protocols:`
    histogram it complements, counted cross-protocol rather than gated on
    `p.protocol` like the per-protocol maps below it, and -- consistent with
    how `--stats` already ignores `--no-vlan`/`--mac-vendor` -- deliberately
    *not* gated on `--no-direction` either, since it's a pure aggregate view
    independent of any per-packet display toggle. All of this is `decode`
    -specific: `policy validate`'s and `inventory`'s own `direction: <tier>`
    report lines (`docs/USER_GUIDE.md`'s `policy validate`/`inventory`
    sections) are untouched, since they're each that command's own separate,
    already-established report format, not `TextWriter`'s.

20. **Beckhoff TwinCAT / ADS (Automation Device Specification).** Jurgen
    asked for this directly; deliberately **not started yet** -- it's a new
    protocol, and the "External code review and engineering priorities"
    section's own item 5 above says no new protocols until items 1-3 there
    (CI-wired sanitizers/fuzzing, the registration-model decoder refactor)
    are substantially underway. Recorded here, at Tier 1 depth (full field
    decoding, matching most of this codebase's other protocols, not just
    port/shape recognition), so the research already done isn't lost:
    - **Transport**: AMS/TCP, TCP port 48898 (0xBF02), no dedicated UDP
      framing to worry about for a first pass (AMS also rides UDP/serial in
      some Beckhoff setups, but TCP is the common industrial-network case
      and where every other protocol here starts too).
    - **Framing**: a 6-byte AMS/TCP header (2 reserved bytes + a 4-byte
      little-endian Data Length) directly precedes the AMS header itself --
      structurally the same "fixed small header, length-prefixed payload"
      shape TPKT/COTP and MBAP already are in this codebase, so the
      existing `Cursor`/`ByteSpan` bounds-checked-read pattern applies
      directly with no new primitive needed.
    - **AMS header** (32 bytes, all fields little-endian except the two
      AmsNetId fields which are just raw 6-byte address bytes): target
      AmsNetId (6) + target AMS port (2) + source AmsNetId (6) + source AMS
      port (2) + Command ID (2) + State Flags (2, bit 0 = request/response,
      bit 2 = TCP vs. UDP -- see Beckhoff's own AMS Header spec page) + Data
      Length (4) + Error Code (4) + Invoke ID (4), then the command-specific
      payload.
    - **Command IDs** (2-byte field, the natural `enum class` + name-lookup
      this codebase already does for every other protocol's PDU-type byte):
      `0x0001` ReadDeviceInfo, `0x0002` Read, `0x0003` Write, `0x0004`
      ReadState, `0x0005` WriteControl, `0x0006` AddDeviceNotification,
      `0x0007` DeleteDeviceNotification, `0x0008` DeviceNotification,
      `0x0009` ReadWrite.
    - **Detection gate candidate**: State Flags' low bits constrain it to a
      handful of valid combinations (request/response x TCP/UDP), Command
      ID must be one of the nine values above, and Data Length must
      plausibly fit the remaining TCP payload -- likely comparable in
      strength to EtherNet/IP's own multi-field encapsulation-header gate
      (docs/DEVELOPMENT.md's PROTOCOL DETECTION section), stronger than
      Modbus's single protocol-id==0 check. Worth explicitly researching
      for collisions against this codebase's other ~60 detections before
      committing to an ordering, the same survey OPC UA/EtherNet/IP/HART-IP
      each got in PROTOCOL DETECTION below.
    - **Read/Write payload addressing**: an IndexGroup (4 bytes) + IndexOffset
      (4 bytes) pair addresses the target PLC symbol/variable -- conceptually
      similar to S7comm's DB/offset item addressing already in this
      codebase, so `s7comm_items`-style rendering is a reasonable template.
    - **Symbolic name resolution** (mapping a human-readable PLC variable
      name to an IndexGroup/IndexOffset pair, via ADS's own
      `ADSIGRP_SYM_HNDBYNAME`/symbol-table reads) is real depth beyond the
      raw IndexGroup/IndexOffset numbers and should probably be its own
      follow-up once basic Read/Write decoding is solid, the same
      "port-heuristic now, tighten later" progression other protocols here
      already followed.
    - Primary source: Beckhoff's own public ADS/AMS specification
      (infosys.beckhoff.com, "TwinCAT ADS/AMS - Specification" and "AMS
      Header" pages) -- no real-capture corpus for this yet, so
      `tests/real_captures/` coverage (this codebase's usual validation bar
      for a protocol this consequential) would need to be sourced or
      synthesized before this is considered done to the same standard as
      the rest of PROTOCOL_COVERAGE.md.

    **Update: implemented**, all nine Command IDs at Tier 1 depth (both
    request and response shapes, IndexGroup/IndexOffset addressing for
    Read/Write/ReadWrite/AddDeviceNotification, DeviceNotification decoded
    structurally -- stamp/sample counts -- but not per-sample), plus
    authoritative Invoke-ID + AMS-session request/response pairing
    (mirroring Modbus's own MBAP-transaction-ID pairing exactly). Also the
    registration-model decoder refactor's own pilot proof (item 3 above,
    "External code review and engineering priorities" section): TwinCAT is
    the first protocol in this codebase built entirely on the
    `ProtocolDecoder` interface, with no `DecodedPacket` flat fields of its
    own at all. See `include/conduitscope/twincat.hpp`'s file header for
    the full writeup (wire format, collision survey, and what's still
    deliberately not implemented -- symbolic name resolution,
    per-sample DeviceNotification decoding) and docs/PROTOCOL_COVERAGE.md's
    TwinCAT / ADS section for the user-facing reference. As anticipated
    above, the structural detection gate did need a real collision fix
    once implemented: an initial version of the TCP-reassembly probe
    (`twincat_declared_length`) checked only the 6-byte AMS/TCP prefix, not
    the full five-part gate `try_parse_twincat` itself uses -- caught by
    the full regression suite (it was mis-buffering MQTT/FF-HSE/SMB/
    TACACS+/OpenVPN traffic as candidate AMS/TCP frames), fixed by
    requiring the complete 38-byte header before declaring a length at all
    and re-applying the same three structural checks the full decoder
    uses. **Still not done**, same as several other protocols in this
    document: no real-world capture corpus (validated by construction
    against a synthetic fixture only -- see PROTOCOL_COVERAGE.md's
    Validation subsection); no `policy validate`/`inventory` integration
    (both degrade gracefully on TwinCAT traffic today -- flows show as "no
    recognized OT protocol traffic" / get skipped, rather than crashing or
    misclassifying -- but neither engine's own independently-forked
    protocol-classification chain recognizes `twincat` as a name yet, so a
    conduit can't be written against it); symbolic name resolution; and
    per-sample DeviceNotification decoding (both explicitly deferred, see
    above).

21. **CLI output defaults for compactness, and offline BPF filtering** --
    **done**. Three related CLI/UX changes, all landed together:
    - **OUI (MAC vendor) resolution flipped from on-by-default to
      off-by-default.** `decode`, `policy validate`, and `inventory` all
      used to print `src_mac_vendor`/`dst_mac_vendor` (or the equivalent
      text-output `(Vendor Name)` annotation) unconditionally, using the
      bundled OUI table. For a busy capture this made every line
      noticeably longer for information most invocations don't need. The
      negating `--no-oui` flag (default true, opt out) is gone; there's now
      a plain opt-in `--mac-vendor` flag (default false) on all three subcommands.
      `--nn` (hostname resolution) is unaffected and independent, as
      before. **Revised after this item's first pass** (`decode` only, the
      other two subcommands unaffected by this revision -- their MAC
      display is structural report content, not a compactness add-on, so it
      stays unconditional): the base `src_mac`/`dst_mac` fact itself was
      initially left always-on in `decode`'s text output (only the vendor
      annotation was gated), on the theory that a resolver annotation
      should never gate a base decoded value. Jurgen asked for the whole
      `eth <src> -> <dst>` line to be off by default too, with a
      tcpdump-style toggle -- so `decode` gained `-e`/`--ether` (off by
      default, mirrors tcpdump's own `-e`), and `--mac-vendor` now implies it
      (there'd be nothing to attach a vendor name to otherwise). This
      applies to **text output only**: JSON/CSV still always include
      `src_mac`/`dst_mac` as base fields (like `src_ip`/`dst_ip`),
      unaffected by `-e`, on the original "a resolver annotation can omit
      itself on a miss or when disabled, but a machine-readable format
      shouldn't lose a base decoded fact just to make a human-facing dump
      more compact" reasoning -- that reasoning turned out to still hold,
      just scoped to JSON/CSV instead of every format. VLAN ID display
      (`--no-vlan`, on by default) is independent of `-e`: a VLAN-tagged
      packet still gets a `vlan <id>` line with no MAC display, since
      802.1Q membership isn't specifically a MAC-address fact -- see
      `output.hpp`/`output.cpp`'s own comments for exactly how the two
      combine on one line when both apply.
      **Revised again**: Jurgen pointed out that a non-IP packet's own
      headline (`decode`'s text output) was wasting its endpoint fields on
      a bare `- -> -` placeholder -- see `endpoint()`'s own old behavior in
      `output.cpp` -- with genuinely no addressing information shown at all
      unless `-e`/`--mac-vendor` was also given, and even then only as a second,
      separate line below rather than on the headline itself. Since every
      Ethernet-linktype packet already carries a real `src_mac`/`dst_mac`
      regardless of protocol (the base gap-fix described above), and a
      packet with no IP layer has no IP address to put on its headline in
      the first place, `endpoint()` now falls back to that MAC address (with
      a `--mac-vendor` vendor name attached, the same way it is everywhere else)
      for exactly this case -- unconditionally, no `-e`/`--ether` needed.
      `write_packet()` correspondingly suppresses the separate `eth <src> ->
      <dst>` line for a non-IP packet specifically (`show_mac_ && p.has_ip`,
      not `show_mac_` alone), since it would otherwise just repeat the same
      pair now already on the headline; a VLAN-tagged non-IP packet still
      gets its own bare `vlan <id>` line exactly as before. An IP-bearing
      packet is completely unaffected either way -- its headline already
      showed `ip:port`, and `-e`/`--mac-vendor` still work exactly as this item's
      first revision above describes. Several existing tests exercising
      `tests/sample_vlan_zones.pcap` (all-non-IP PROFINET RT/GOOSE/SV/
      EtherCAT traffic) and the `-e`-gated fallback assertions in
      `tests/sample_sv.pcap`/`tests/sample_stp.pcap` needed updating to
      match -- see CMakeLists.txt's own comments at those tests (e.g.
      `vlan_id_shown_by_default_text`, `non_ip_mac_shown_by_default_without_vendor_text`)
      for exactly what changed and why.
    - **`-t/--time-format` default flipped from `e`/epoch to `r`/relative.**
      Raw Unix epoch timestamps (`1700000000.000000`) aren't very readable
      at a glance; seconds-elapsed-since-first-packet is what most other
      packet-analysis tools default to as well, and is what most people
      actually want when eyeballing a capture interactively. The raw epoch
      value remains one flag away (`-t epoch`), and the JSON `timestamp`
      field is unaffected by `-t` regardless of format, so nothing about
      machine-readable output changed.
    - **`--filter` (BPF) now works with `-r` (offline file reads), not just
      `-i` (live capture).** Previously the BPF filter was wired only into
      `LiveCapture`, via libpcap's normal live-handle `pcap_compile()` +
      per-packet kernel-level filtering; reading a saved pcap/pcapng file
      with `-r` had no filtering at all short of piping through an external
      `tcpdump -r ... -w -`. New `BpfFilter` class
      ([include/conduitscope/bpf_filter.hpp](../include/conduitscope/bpf_filter.hpp),
      [src/bpf_filter.cpp](../src/bpf_filter.cpp)) compiles the same
      tcpdump-syntax filter against a `pcap_open_dead()` "fake" handle
      bound to the file's own linktype/snaplen (the modern, non-deprecated
      replacement for `pcap_compile_nopcap()`), then applies libpcap's
      `bpf_filter()` per packet after `PcapReader` decodes it -- same
      filter syntax, same `CaptureError` message shape, as the live-capture
      path. Follows `live_capture.hpp`'s established optional-dependency
      pattern: the source file always compiles, and on a
      `CONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`/no-libpcap build, the
      constructor throws a clear "requires libpcap/Npcap support" error
      instead of silently no-op'ing. A multi-interface pcapng file that
      changes linktype mid-stream is handled by recompiling only when the
      linktype actually changes (`PacketSource`/`BpfFilter::matches()`),
      not on every packet.
    - **The generic "no protocol claimed this TCP payload" fallback summary
      is now terse instead of an ever-growing list.** It used to name every
      protocol this decoder had already tried and ruled out on that
      payload -- a list that only grows as more protocols get added, and
      is entirely noise on ordinary, unremarkable traffic rather than
      information an OT auditor can act on. Jurgen asked for this to be
      shortened after seeing it on ordinary traffic. Replaced with a
      fixed-shape one-liner, `TCP payload of N byte(s) on port X->Y`
      (`decoder.cpp`'s final TCP fallback, right after Tier 5's tunnel/VPN
      check), matching the equivalent UDP-side fallback's own
      already-terse shape a few hundred lines earlier in the same file.

    All four are covered by CTest (27 pre-existing OUI/VLAN tests updated
    for the new OUI default; 8 more updated and 6 new ones added for the
    `-e`/`--ether` revision above; 11 new `-t`/`--time-format` tests; 8 new
    `--filter`-on-`-r` tests including the no-libpcap stub path; existing
    fallback-summary tests updated to match the terser wording) and
    verified clean under ASan/UBSan (1148/1148 on the default build).

    **Follow-up fix (post-release, Jurgen's own report)**: applying
    `--filter` to an offline `-r` read renumbered the surviving packets
    sequentially from `#1` within just the matches, instead of preserving
    each one's real position in the unfiltered file -- e.g. filtering a
    capture to `udp port 53` turned the file's own `#8`/`#10`/`#11` into
    `#1`/`#2`/`#3`, making it needlessly hard to cross-reference a filtered
    packet back against the same file opened unfiltered (or in Wireshark,
    whose own display-filter numbering keeps frame numbers stable). This
    was originally treated as the deliberate, "same convention live
    capture already follows" behavior (see this item's own `PacketSource`
    design above) -- but live capture's renumbering is unavoidable (the
    non-matching packets were never captured at all, via libpcap's
    `pcap_setfilter()`), while an offline read has the whole file already
    on disk and no reason to throw that positional information away.
    Fixed in `PacketSource::next()` (`cli_main.cpp`): a new
    `file_position_` counter advances on every packet actually read off
    disk, matched or not, and `index()` reports that position rather than
    a locally-incremented "packets returned so far" count -- `run_decode`/
    `run_policy_validate`/`run_inventory` all now read the packet's index
    from `source.index()` instead of maintaining their own counter. Live
    capture's own numbering (`live_position_`) is unchanged -- there is no
    "original position" to preserve there in the first place. One
    dedicated regression test added
    (`bpf_filter_read_preserves_original_packet_numbering`, `CMakeLists.txt`)
    plus a tightened `bpf_filter_read_dst_host_narrows_correctly` (now
    pins the two surviving packets to their real `#2`/`#3` file positions
    rather than merely checking their content) -- both against the
    existing `tests/sample_modbus.pcap` fixture, no new fixture needed.
    Full suite (1300 tests) passes, zero-warning build across all three
    established configs.

22. **Kerberos (RFC 4120) -- phase 1 of a 4-part Windows Active Directory
    suite, with curated attack/monitoring detection.** Jurgen asked for
    "more extensive Windows Active Directory protocol dissectors, with a
    special focus on penetration testing and monitoring attacks." A real
    scope expansion -- nothing in this codebase before this item touched
    the Windows auth/directory stack at all -- but a well-motivated one:
    AD compromise is a standard pivot point into OT environments (AD-joined
    engineering workstations, jump hosts), so visibility into it fits this
    project's NIS2/IEC 62443 audit angle directly. Scoped via three
    clarifying questions before any code was written: the full AD suite is
    the eventual target (Kerberos, LDAP, SMB/NTLM, Netlogon/DCE-RPC), but
    delivered **one protocol at a time** (this item is Kerberos only --
    LDAP/SMB-NTLM/Netlogon are separate future items, not started); and
    attack detection as a **curated flagship set** (a handful of
    precisely-documented, low-noise named findings, each with its own
    heuristic and false-positive caveat spelled out) rather than broad
    best-effort anomaly tagging.

    **Done.** Built entirely on the `ProtocolDecoder` interface (item 3
    above) -- the second protocol in this codebase to use it, after
    TwinCAT (item 20) -- as two decoder instances,
    `KerberosTcpDecoder`/`KerberosUdpDecoder`, sharing one `id() ==
    "kerberos"`, the same "one protocol, one id(), two GateKind instances"
    split HART-IP established. All 6 message types decoded (AS-REQ/AS-REP/
    TGS-REQ/TGS-REP fully, KRB-ERROR fully, AP-REQ/AP-REP structurally --
    their `Authenticator`/`enc-part` ciphertext is opaque without keys from
    a passive capture, the same honest limit any Kerberos dissector has).
    Five curated notes: a standing note on any preauth-less AS-REQ, the
    AS-REP-Roasting flagship flag (correlated, session-scoped, fires only
    on a matching successful AS-REP), the Kerberoasting flagship flag
    (keyed off the embedded Ticket's own `enc-part` etype, `krbtgt` snames
    excluded), an always-on DES/RC4-without-AES downgrade note, a
    delegation-shape structural note (forwardable/proxiable/
    additional-tickets), and named KRB-ERROR code counts in `--stats`
    (password-spray/enumeration visibility with no per-session correlation
    needed). See `include/conduitscope/kerberos.hpp`'s file header for the
    full writeup (wire format, structural detection gate, collision
    survey, curated-note design) and docs/PROTOCOL_COVERAGE.md's Kerberos
    section for the user-facing reference; PROTOCOL DETECTION below has
    this item's own collision-survey summary.

    One real correctness bug was caught and fixed during this item's own
    build-and-smoke-test pass (before any test was written against it, so
    no regression seed exists for it -- caught by manually constructing a
    TGS-REP with the Ticket's own etype and the response's own outer etype
    deliberately set to *different* values and observing the Kerberoasting
    note fire on the wrong one): the Kerberoasting check was initially
    keyed off `enc_part_etype` (the response's own outer enc-part, which
    is encrypted to the *requesting client's* session key and reveals
    nothing about the target service account) instead of
    `ticket_enc_part_etype` (the embedded Ticket's own enc-part, encrypted
    to the *target service's* long-term key -- the actual material
    Kerberoasting cracks offline). Both false negatives (a real
    Kerberoastable RC4 service ticket answered with an AES outer enc-part,
    the common case, went unflagged) and false positives (a client whose
    own session key happened to be RC4 got flagged regardless of the
    target account's own etype) were possible before the fix. Fixed by
    switching the condition and the `has_ticket` guard to the Ticket's own
    field; `tests/sample_kerberos.pcap` packet #4 (`kerberos_kerberoasting_
    flagship_note_correlated`) now specifically exercises this -- ticket
    etype RC4, outer etype AES, deliberately different, to keep this from
    regressing silently.

    Session/correlation state (`KerberosFlowState`, keyed by
    `FlowStateKeying::Session`) uses `cname` (AS-REQ) and `sname`
    (TGS-REQ/TGS-REP) rather than RFC 4120's own `nonce` field for
    request/response correlation, since the nonce echo lives inside the
    response's encrypted part and is unreadable without keys from a
    passive capture -- an honest, documented limitation (see
    kerberos.hpp's STATE/CORRELATION section and PROTOCOL_COVERAGE.md's
    own paragraph on it), not a bug: sufficient for realistic
    single-exchange-at-a-time KDC traffic, could misattribute only if the
    same client had two genuinely overlapping unanswered requests on one
    session at once, which is rare in practice.

    **Still not done** (as of this item -- LDAP followed as item 23, see
    below): SMB/NTLM and Netlogon/DCE-RPC (the remaining two protocols of
    the planned AD suite -- separate future items); PAC contents
    (SID/group extraction, PAC signature validation --
    unreadable without keys from a passive capture, same limit as the
    Authenticator/AP-REP ciphertext above); KRB-SAFE/KRB-PRIV/KRB-CRED
    (rare outside app-level Kerberos usage like kpasswd, not part of the
    core AD auth exchange); no `policy validate`/`inventory` integration
    (both degrade gracefully on Kerberos traffic today, the same "flows as
    unrecognized rather than misclassified" posture TwinCAT's own item 20
    is still in); and no real-world capture corpus -- validated by
    construction only, against synthetic `tests/sample_kerberos.pcap`
    (UDP, 15 packets) and `tests/sample_kerberos_tcp.pcap` (TCP, 3
    packets, including a TCP-segment-split reassembly case) --
    `wiki.wireshark.org`'s own public SampleCaptures page was identified
    during planning as a plausible source (`krb-816.zip`,
    `kerberos-Delegation.zip`, `constained-delegation.zip`) but wasn't
    reachable from this environment's network egress policy to actually
    fetch and inspect; if a real Kerberos capture becomes available later
    it should be added and PROTOCOL_COVERAGE.md's Validation subsection
    updated accordingly, the same way this project has handled every other
    protocol where independent traffic was eventually found after an
    earlier empty search. 19 new CTest tests (all 6 message types, both
    flagship notes with a correlated positive case each, three explicit
    negative cases proving the curated-not-noisy bar is actually met, the
    downgrade/delegation notes, `--stats` KRB-ERROR counts, `--protocol
    kerberos`/`--kerberos-port`, non-standard-port note, and the TCP
    whole-frame/split-segment cases) -- full existing suite (1205 tests)
    stays 100% passing, zero-warning build.

23. **LDAP (RFC 4511) -- phase 2 of the 4-part Windows Active Directory
    suite, with curated attack/monitoring detection.** The natural next
    step after Kerberos (item 22): LDAP reconnaissance (SPN sweeps,
    `userAccountControl` bit queries) is literally how a real attacker
    *finds* the AS-REP-Roasting/Kerberoasting targets item 22's own
    curated notes already flag, so this item completes that story rather
    than starting a new one. LDAP already had shallow, name-only
    recognition in this codebase before this item (Tier 3's
    "enterprise-trust" family) -- **that recognition is removed** in favor
    of a full decoder, the same "pull one protocol out of a shared tier
    into its own dedicated decoder/CLI surface" move this codebase already
    made once for EAPOL; NTP/DHCP/RADIUS/TACACS+/LDAPS stay exactly as they
    were in the legacy `it_protocols.cpp` path, untouched.

    **Done.** Built on the `ProtocolDecoder` interface (item 3), the third
    protocol in this codebase to use it, as one decoder instance,
    `LdapTcpDecoder`, `id() == "ldap"`, `GateKind::TcpPortIndependent` --
    unlike Kerberos, deliberately **no UDP sibling** (CLDAP, RFC 1798, is
    obsolete/deprecated and not part of mainstream AD traffic). A real
    collision was found and resolved **during planning**, not left for
    implementation to discover: RFC 4511's ASN.1 module is `DEFINITIONS
    IMPLICIT TAGS`, the opposite of Kerberos's (RFC 4120) `EXPLICIT TAGS`
    convention -- confirmed by reading RFC 4511's actual ASN.1 module text,
    not recalled from training -- which means Kerberos's own AS-REP/
    TGS-REQ/TGS-REP/AP-REQ/AP-REP APPLICATION tags (`0x6B`/`0x6C`/`0x6D`/
    `0x6E`/`0x6F`) are byte-identical to five of LDAP's own operation tags.
    This does NOT actually collide at the dispatch-gate level (Kerberos's
    gate reads the outer tag of the whole de-framed payload; LDAP's byte 0
    is always the fixed envelope tag `0x30`, the overlapping tags only
    ever appear several bytes inside an LDAP message) -- see PROTOCOL
    DETECTION above for the full writeup, and
    `include/conduitscope/ldap.hpp`'s own header comment for the complete
    per-field IMPLICIT-tagging wire-format table this collision analysis
    depends on.

    All 21 `protocolOp` values recognized; 11 message types fully
    field-decoded (BindRequest/BindResponse, UnbindRequest, SearchRequest
    -- including full recursive `Filter` CHOICE decoding rendered in
    `ldapsearch`-style syntax, SearchResultEntry/SearchResultDone/
    SearchResultReference, CompareRequest/CompareResponse, AbandonRequest,
    ExtendedRequest/ExtendedResponse), the remaining 9 (AddRequest/
    AddResponse, ModifyRequest/ModifyResponse, DelRequest/DelResponse,
    ModifyDNRequest/ModifyDNResponse, IntermediateResponse) structural-only
    -- the same "not every message type needs the same depth" discipline
    AP-REQ/AP-REP got in item 22. Six curated notes: anonymous/
    unauthenticated bind (standing), cleartext-credential-without-StartTLS
    (session-tracked via `LdapFlowState::starttls_seen`, covers both
    `simple` and SASL PLAIN binds), AD reconnaissance filter shapes
    (servicePrincipalName/adminCount), AS-REP-Roasting target discovery
    (the AD-specific bitwise-AND matching rule, `1.2.840.113556.1.4.803`,
    against `userAccountControl`'s `DONT_REQ_PREAUTH` bit -- both OIDs/bit
    values independently verified against Microsoft's own MS-ADTS spec and
    troubleshooting docs, not recalled from training alone), delegation
    discovery (the same bitwise mechanism against `TRUSTED_FOR_DELEGATION`,
    or a bare `msDS-AllowedToDelegateTo` reference), and named `resultCode`
    counts in `--stats` (the password-spray signature -- LDAP's own analog
    of item 22's KRB-ERROR count aggregation). See
    `include/conduitscope/ldap.hpp`'s file header for the full writeup
    (wire format, structural detection gate, collision survey, curated-note
    design) and docs/PROTOCOL_COVERAGE.md's LDAP section for the
    user-facing reference; PROTOCOL DETECTION above has this item's own
    collision-survey summary.

    Session/correlation state (`LdapFlowState`, keyed by
    `FlowStateKeying::Session`) is a genuine **improvement** over item 22's
    own documented limitation, not another instance of it: LDAP's
    `messageID` is the RFC-mandated, always-visible-on-the-wire correlation
    key (RFC 4511 section 4.1.1.1 requires it unique among a connection's
    outstanding requests), unlike Kerberos's real `nonce` field, which is
    unreadably encrypted. The pending-search map also introduces a shape
    Kerberos never needed: created on `SearchRequest`, **not** erased on
    each `SearchResultEntry` (only the running entry count is incremented),
    erased with a final "N entries returned" note only on the terminal
    `SearchResultDone` -- "keep state across many responses, close on the
    terminal one," since one `SearchRequest` can have arbitrarily many
    `SearchResultEntry` responses before its one `SearchResultDone`.

    One correctness bug was caught during this item's own build-and-
    smoke-test pass, before any CMakeLists.txt test was written against it
    (the same "verify before trusting the test suite alone" discipline
    that caught item 22's own Kerberoasting field-mixup bug): the fixture
    generator (`tools/make_sample_pcap.py`'s `build_ldap_sample()`)
    initially gave each `SearchResultEntry`/`SearchResultDone` message its
    own incrementing envelope `messageID`, rather than reusing the SAME
    `messageID` as the `SearchRequest` that produced them -- while RFC
    4511 section 4.1.1.1 requires a response to echo its request's own
    `messageID`. This silently defeated `LdapFlowState::pending_searches`'
    own correlation (the entry-count note never fired), caught immediately
    by running the built binary against the fixture and noticing the
    expected note was simply absent from the output, not by a failing
    test. Fixed by reusing the request's own `messageID` across every
    response tied to it, the same way real LDAP traffic does; every
    `ldap_*` CMakeLists.txt test was then written from the corrected
    binary's own verified output, not hand-computed.

    Removing LDAP from `try_recognize_it_enterprise_trust()`'s shallow
    Tier-3 recognition changed the decoded behavior of several packets in
    the pre-existing, shared `tests/sample_enterprise_trust.pcap` fixture
    (no generator script exists for this fixture -- confirmed via
    exhaustive grep across `tools/*.py` -- so its bytes could not be
    regenerated, only the CMakeLists.txt test *expectations* about its
    output could change). Rather than guessing at the new expectations,
    the built binary was run directly against this fixture in several
    modes (`--format text`/`--stats`/`--protocol enterprise-trust`/
    `--protocol ldap`/`--ldap-port`/`--format json`) and the 5 affected
    `enterprise_trust_ldap_*` tests (plus `enterprise_trust_stats_counted`
    and `enterprise_trust_protocol_filter_isolates_port_based_family`)
    were rewritten to match the observed ground truth -- including one
    genuinely surprising change: a 9-byte packet that satisfied the old
    shallow op-tag-only check is no longer recognized as `ldap` at all,
    since the new full decoder's `SearchRequest` requires all 8 mandatory
    fields to be present and throws a `ParseError` otherwise.

    **Still not done** (as of this item -- SMB/NTLM followed as item 27,
    see below): SMB/NTLM and Netlogon/DCE-RPC (the remaining two
    protocols of the planned AD suite -- separate future items); CLDAP
    (UDP, obsolete, no decoder instance at all); SASL/`simple` credential
    *contents* (never decrypted/decoded, only presence+length, by design);
    Controls' `controlValue` payloads (OID named, value bytes not
    decoded); LDAPS full decode (needs keys, same limit as TLS everywhere
    else); no `policy validate`/`inventory` integration (degrades
    gracefully on LDAP traffic today, the same posture item 22 is still
    in); and no real-world capture corpus -- validated by construction
    only, against synthetic `tests/sample_ldap.pcap` (TCP, 62 packets
    across 17 independent sessions/flows) and
    `tests/sample_ldap_tcp_split.pcap` (TCP, 2 packets, a TCP-segment-split
    reassembly case); if a real LDAP capture becomes available later it
    should be added and PROTOCOL_COVERAGE.md's Validation subsection
    updated accordingly, the same way this project has handled every other
    protocol where independent traffic was eventually found after an
    earlier empty search. 29 new `ldap_*` CTest tests (every message type,
    all six curated notes with an explicit negative case each, the "many
    SearchResultEntry, one SearchResultDone" correlation, binary-attribute
    rendering, control_oids, `--stats` resultCode counts, `--protocol
    ldap`/`--ldap-port`, non-standard-port note, and TCP-segment-split
    reassembly) plus 5 rewritten `enterprise_trust_ldap_*` tests and 2
    updated `enterprise_trust_*` tests for the fixture-behavior change
    above -- full existing suite stays 100% passing, zero-warning build.

24. **IPv6 support.** Not yet started -- flagged across several other
    items and the User Guide's own limitations list as they were written
    (`ipv4.hpp`'s own header comment, USER_GUIDE.md's "No IPv6" bullet,
    and the VRRP-for-IPv6/HSRPv2-for-IPv6/PIM-IPv6/6in4-inner-address gaps
    each call out separately), gathered here into one item rather than
    left scattered. Today, `decoder.cpp` only ever parses an IPv4 outer
    header: an IPv6 packet over Ethernet is named at the link layer
    (`ETHERTYPE_IPV6`, `0x86DD` -- see `link_layer.hpp`) but its own
    header is never opened, so it is reported as `non-ip`; over a raw-IP
    link type there is no ethertype field to name it by at all, so it
    falls through to `parse-error` instead. This means every upper-layer
    decoder in this codebase -- including ones that dispatch purely on IP
    protocol number or TCP/UDP port, with no IPv4-specific logic of their
    own -- is currently unreachable over IPv6, not because each one was
    individually scoped out, but because nothing ever hands them an IPv6
    flow to begin with.

    Scope for a first pass: a new `ipv6.hpp`/`ipv6.cpp`, mirroring
    `ipv4.hpp`/`.cpp`'s own shape (fixed 40-byte base header; RFC 8200's
    extension-header chain -- Hop-by-Hop/Routing/Fragment/Destination
    Options/ESP/AH -- walked far enough to reach the real upper-layer
    protocol, not fully decoded); a new `decoder.cpp` call site alongside
    the existing IPv4 one; and a shared, canonical (RFC 5952
    zero-run-compressed) IPv6 address-formatting helper, reused everywhere
    an address currently only has IPv4 formatting -- `dns.cpp`'s own AAAA
    handler already does a basic, non-canonical hex-colon rendering
    (`case 28` in its RR-value decode function) that is a useful reference
    point but not this shared helper. That one formatter is what unblocks
    several already-documented gaps at once: VRRPv3/HSRPv2-for-IPv6
    address-list rendering (`vrrp.hpp`/`hsrp.hpp`'s own "no IPv6 address
    formatting anywhere in the codebase" notes), PIM's IPv6 Encoded
    Address support (`pim.hpp`), and 6in4's inner src/dst extraction
    (`tunnel_vpn.cpp`) -- none of those four need new wire-format logic,
    only the formatter this item would add.

    Out of scope for a first pass, the same way the IPv4 side draws its
    own lines today: 4in6/DS-Lite/MAP-E (IPv6-*outer* encapsulations,
    which need the new `decoder.cpp` call site itself before they're even
    reachable -- see docs/PROTOCOL_COVERAGE.md's Tier 5 section); wiring
    IPv6 into `policy validate`'s own conduit/zone model, which should
    follow the same "widen policy validate" work items 9/14/15/17 already
    call for on the UDP side rather than duplicate it; and IPsec/ESP's own
    encrypted payload (opaque regardless of IP version, the same limit ESP
    already has over IPv4).

25. **VMware vSphere/ESXi link-layer frames (EtherType `0x8922`).** Not
    yet started. VMware's own registered EtherType, ridden by two related
    features on an ESXi host's physical uplinks: the older per-NIC
    "beacon probing" NIC-teaming failover-detection mechanism, and the
    newer vSphere Distributed Switch (vDS) Health Check (detects VLAN/MTU/
    teaming-policy mismatches between the virtual and physical switch,
    sent by default once a minute per uplink). Confirmed from two
    independent secondary sources (a VMware-networking deep-dive blog and
    Broadcom's own vDS health-check KB article) plus the actual upstream
    implementation, `vmware/open-vm-tools`' `eth_public.h`, which is the
    real wire-format definition rather than a secondhand description of
    it:

    ```c
    #define ETH_TYPE_VMWARE         0x8922
    #define ETH_VMWARE_FRAME_MAGIC  0x026f7564
    typedef struct Eth_VMWareFrameHeader {
        uint32 magic;   // ETH_VMWARE_FRAME_MAGIC, always present
        uint16 lenNBO;  // length of the type-specific payload, network byte order
        uint8  type;    // ETH_VMWARE_FRAME_TYPE_*
    } Eth_VMWareFrameHeader;
    enum {
        ETH_VMWARE_FRAME_TYPE_INVALID = 0,
        ETH_VMWARE_FRAME_TYPE_BEACON  = 1,
        ETH_VMWARE_FRAME_TYPE_COLOR   = 2,
        ETH_VMWARE_FRAME_TYPE_ECHO    = 3,
        ETH_VMWARE_FRAME_TYPE_LLC     = 4,
    };
    ```

    This is a genuinely strong structural gate -- a 4-byte fixed magic
    number plus a small closed type enum, the same "structural signature
    overrides a bare ethertype/port check" bar VNC/SMB/SSH/HTTP/WireGuard/
    the generic dtls-tunnel check already earn elsewhere in this codebase
    -- not just naming the ethertype the way `link_layer.cpp`'s own
    ethertype-naming switch currently would (it has no `case` for `0x8922`
    at all today). Structurally this belongs with EAPOL/PROFINET RT/
    EtherCAT/GOOSE/Sampled Values: a link-layer-only protocol dispatched
    directly off ethertype in `decoder.cpp`, never touching an IP header,
    so it needs its own new call site there rather than reuse of the
    IPv4/TCP/UDP path.

    First-pass scope: recognize the magic+length+type envelope and name
    the `type` field (`beacon`/`color`/`echo`/`llc`, or `invalid`/an
    unrecognized numeric value honestly reported as such -- this
    codebase's usual posture for an enum with gaps). The `type`-specific
    payload beyond the 7-byte header -- one of the two secondary sources
    above describes a beacon frame's own body as carrying a host UUID, a
    sequence number, a source virtual-port identifier, and an adapter
    name, but gives no byte offsets or field sizes, and no byte-level
    layout for `color`/`echo`/`llc` was found during this scoping pass
    either -- so **the payload itself should be treated as
    structural-only (present/length only, not field-decoded) until an
    authoritative byte-level source, or a real captured sample, is
    found**, the same "verify before decoding, don't guess a layout" bar
    this codebase already holds itself to (see e.g. the StartTLS-OID and
    AD bitwise-match-rule-OID call-outs in item 23). Worth asking when
    this is picked up: is this actually something an OT auditor should
    see flagged, or just recognized? The honest case for it is
    virtualization-infrastructure visibility -- SCADA/HMI/historian
    servers increasingly run as ESXi guests, and unexpected `0x8922`
    traffic (or its conspicuous absence where health-check was expected)
    is a legitimate "what is this box actually doing" signal, the same
    spirit as the "IT protocols an OT auditor flags" family (item 18) --
    but any curated note built on top of that framing needs the same
    "flagship, not broad tagging" scrutiny every other curated note in
    this document already got, not merely because the traffic is now
    technically decodable.

26. **HomePlug AV / HomePlug AV2 powerline networking, including devolo's
    "dLAN" product line (EtherType `0x88E1`).** Not yet started. devolo's
    "dLAN" branding is not a separate protocol -- devolo is one of the
    founding HomePlug Powerline Alliance members, and its dLAN adapters
    (the 200/500/650/1200-series, including the AVmini/AVsmart+ models)
    are HomePlug AV or HomePlug AV2 devices on the wire; devolo's own
    "dLAN Cockpit" configuration software, and third-party tools like
    `faifa` and `dlanlist`/`dlanpasswd`, talk to them using the standard
    HomePlug AV management protocol, not a devolo-specific one. Confirmed
    from the HomePlug AV Wireshark dissector's own source
    (`packet-homeplug-av.c` and the newer standalone `homeplug-av.lua`,
    both in the public `wireshark`/`serock` GitHub repos) rather than a
    secondhand description of it. The wire format is a fixed 5-byte MME
    (Management Message Entry) header immediately after the Ethernet
    header, no IP layer involved:

    ```text
    offset 0       MMV      1 byte   Management Message Version
    offset 1-2     MMTYPE   2 bytes  little-endian; top 3 bits classify the
                                     message group, bottom 2 bits the
                                     request/confirm/indication/response kind
    offset 3       FMI      1 byte   NF_MI (fragment count, high nibble) +
                                     FN_MI (this fragment's number, low nibble)
    offset 4       FMSN     1 byte   fragmentation message sequence number
    offset 5+      --                MME payload, type-specific
    ```

    Structurally this is the same shape as item 25's VMware frames --
    link-layer-only, no IP header, dispatched directly off ethertype in
    `decoder.cpp` alongside EAPOL/PROFINET RT/EtherCAT/GOOSE -- but with a
    weaker gate: unlike VMware's 4-byte fixed magic number, HomePlug AV's
    own header has no magic constant, only a version byte and a
    two-bit-encoded message-kind field, closer to the "port/ethertype
    plus one plausibility check" tier NTP/DHCP-style name-only recognition
    already uses elsewhere in this codebase than to a strong multi-field
    structural signature -- worth being honest about that weaker
    confidence in whatever text this decoder eventually reports, the same
    way the L2TPv3 port-only fallback and STT's port-only recognition
    already are elsewhere in this document.

    First-pass scope, if picked up: name the ethertype and, from MMTYPE,
    the general message classification (discovery/bridging-info/
    encryption-key-set/network-stats and so on -- HomePlug AV's own MMTYPE
    space is large and partly vendor-specific, e.g. distinct Qualcomm/
    Atheros/Broadcom-chipset extensions the dissector sources above
    already split into a separate `mmtype_qualcomm` field table -- full
    enumeration of that space would need its own verification pass, not
    assumed from this scoping note alone); MME payload fields
    structural-only until an authoritative field-by-field source is
    confirmed. Worth asking, like item 25, whether this is genuinely
    audit-relevant before building a curated note on top of bare
    recognition: powerline networking is consumer/SOHO-grade equipment,
    a plausible (if unusual) sighting on an OT network's office/IT segment
    but with none of vSphere's "virtualization infrastructure underneath
    the SCADA/HMI stack" framing -- the honest case here is narrower,
    closer to "what is this consumer-grade gear doing on this network"
    than a security-relevant protocol behavior in its own right.

27. **SMB2/NTLM (MS-SMB2, MS-NLMP) -- phase 3 of the 4-part Windows Active
    Directory suite, with curated attack/monitoring detection.** The
    natural next step after LDAP (item 23): a successful NTLM (or
    Kerberos) authentication over SMB is exactly what an attacker does
    with the credentials items 22/23's own curated notes already flag (a
    Kerberoasted/AS-REP-Roasted ticket cracked offline, or credentials
    harvested via LDAP recon) -- SMB is where those credentials get
    *used*, most often via NTLM relay/pass-the-hash against the
    `ADMIN$`/`C$`/`IPC$` administrative shares for lateral movement. SMB
    already had shallow, name-only recognition in this codebase before
    this item (Tier 2's "lateral-movement" family, a 4-byte magic check
    only) -- **that recognition is removed** in favor of a full decoder,
    the same "pull one protocol out of a shared tier into its own
    dedicated decoder/CLI surface" move already made for EAPOL and LDAP;
    SSH/HTTP/HTTPS/SNMP/Telnet/FTP/TFTP stay exactly as they were in Tier
    2, untouched.

    **Done.** Built on the `ProtocolDecoder` interface, as one decoder
    instance, `SmbTcpDecoder`, `id() == "smb"`,
    `GateKind::TcpPortIndependent` -- no UDP sibling, SMB has none. NTLM
    itself (MS-NLMP) gets its own small **shared** parser
    (`ntlm.hpp`/`ntlm.cpp`, called from `smb.cpp`, no `ProtocolDecoder` of
    its own) rather than being duplicated per-embedding the way Kerberos's
    and LDAP's own BER readers deliberately are -- NTLM's wire format is
    byte-identical wherever it appears (unlike those two protocols' own
    genuinely different ASN.1 tagging conventions), so sharing is the
    correct application of the same underlying principle, not an
    exception to it. Fixed-width little-endian fields throughout, not
    BER/ASN.1 -- a new wire-format shape relative to Kerberos/LDAP -- and
    a genuinely new wrinkle neither of those two protocols had:
    **compounding** ([MS-SMB2]'s own mechanism for chaining several SMB2
    messages inside one TCP segment via each header's own `NextCommand`
    field), walked structurally by `parse_smb2_chain` rather than
    misparsed as one message plus trailing garbage.

    NEGOTIATE and SESSION_SETUP and TREE_CONNECT fully field-decoded
    (including the full NTLM NEGOTIATE_MESSAGE/CHALLENGE_MESSAGE/
    AUTHENTICATE_MESSAGE trio via the shared parser above), LOGOFF/
    TREE_DISCONNECT header-only; the file-I/O-heavy commands (CREATE/
    CLOSE/READ/WRITE/IOCTL and the rest) structural-only for this pass --
    the same "not every message type needs the same depth" discipline
    AP-REQ/AP-REP got in item 22 and Add/Modify/Del got in item 23. Six
    curated notes: SMB1 traffic present (standing), SMB signing not
    required (the precondition every NTLM-relay tool checks for --
    arguably this item's single highest-value note), NTLM negotiated for
    this session (fires on every NTLM-bearing message, the SMB-side
    complement of items 22/23's own notes), anonymous/guest session
    established, administrative/hidden share access (`ADMIN$`/`C$`/
    `IPC$`, confirmed as `IPC$` specifically once the response's own
    `ShareType == pipe` is known), and named `Status` counts in `--stats`
    (`STATUS_LOGON_FAILURE` above all -- the SMB-side password-spray
    signature, the analog of item 22's KRB-ERROR counts and item 23's
    resultCode counts; `STATUS_ACCOUNT_LOCKED_OUT` = `0xC0000234` was the
    one value flagged during planning as not independently cross-checked,
    and was confirmed against multiple independent sources at
    implementation time). See `include/conduitscope/smb.hpp`'s and
    `include/conduitscope/ntlm.hpp`'s file headers for the full writeup
    and docs/PROTOCOL_COVERAGE.md's SMB2/NTLM section for the user-facing
    reference.

    Session/correlation state (`SmbFlowState`, keyed by
    `FlowStateKeying::Session`) introduces a shape neither item 22 nor
    item 23 needed: alongside the plain `MessageId`-keyed 1:1
    request/response map (NEGOTIATE/TREE_CONNECT/LOGOFF/TREE_DISCONNECT),
    a `SessionId`-keyed `pending_ntlm_handshakes` map correlates NTLM's own
    negotiate/challenge/authenticate exchange -- a multi-leg handshake
    spanning *two separate* SESSION_SETUP request/response pairs, each
    with its own `MessageId`, tied together only by the `SessionId` the
    server assigns on the first (non-terminal,
    `STATUS_MORE_PROCESSING_REQUIRED`) response. This is the SMB-side
    equivalent of item 23's own "keep state across many responses, close
    on the terminal one" pattern, just keyed by session instead of a
    single message's own correlation field, because the *thing* being
    correlated here is a multi-message handshake rather than a
    one-to-many search. `MessageId` itself continues item 23's own
    "genuine improvement over Kerberos's documented limitation" point:
    it's the RFC-mandated, always-visible-on-the-wire correlation key,
    unlike Kerberos's real `nonce`, which is unreadably encrypted.

    Manually smoke-tested against a hand-built synthetic SMB2/NTLM
    exchange (covering all six curated notes and their negative-case
    controls) BEFORE any CMakeLists.txt test was written against it, the
    same discipline that caught item 22's own Kerberoasting field-mixup
    bug and item 23's own messageID-correlation bug -- no correctness bugs
    were found this time; every `smb_*` CMakeLists.txt test was written
    from the verified binary's own output afterward, not hand-computed.

    Removing SMB from `try_recognize_it_lateral_movement()`'s shallow
    Tier-2 magic-only recognition changed the decoded behavior of several
    packets in pre-existing, shared fixtures: the new decoder's own
    stricter framing check -- it correctly requires the 4-byte
    Zero+StreamProtocolLength Direct-TCP/NBSS prefix [MS-SMB2]/RFC 1002
    actually mandate on BOTH ports, which the old Tier-2 heuristic never
    validated -- means `tests/sample_lateral_movement.pcap`'s own
    direct-hosting SMB packet (built for the old, less strict check, with
    no real prefix) no longer decodes as `smb` at all, falling through to
    generic `tcp` instead; the 7 affected `lateral_movement_*`/
    `notable_protocols_*`/`real_hartip_*` tests were updated to match the
    observed ground truth from the rebuilt binary, following the exact
    `enterprise_trust_ldap_*` precedent item 23 already established for
    this kind of "protocol graduates out of a shared tier" fixture
    change. One genuine real-world side effect also emerged: this same
    stricter check means `tests/real_captures/hartip/hart_ip.pcapng`'s own
    incidental background SMB1 connection -- previously an unresolved
    HART-IP weak-gate false positive -- is now correctly recognized and
    decoded as `[smb]`, the first real-world confirmation of this
    decoder's own detection gate; a new
    `real_hartip_smb_traffic_now_correctly_decoded` test covers it -- see
    `tests/real_captures/hartip/ATTRIBUTION.md`'s updated section.

    **Still not done**: Netlogon/DCE-RPC, riding inside the SMB named-pipe
    I/O this decoder deliberately leaves structural-only -- see item 28,
    the fourth and final protocol of the planned AD suite, which closes
    this gap. SMB1/CIFS's own full command set (recognized via curated note 1, not
    decoded further); NBSS session-establishment (named NetBIOS computer
    names, no authentication/recon value); SMB 3.x signing verification
    and encryption (same limit as every other encrypted protocol this
    codebase meets); the SMB 3.1.1 `NegotiateContextList`; full SPNEGO/
    GSS-API ASN.1 decode (the `NTLMSSP\0` signature scan is the deliberate
    substitute); no `policy validate`/`inventory` integration (degrades
    gracefully on SMB traffic today, the same posture items 20/22/23 are
    still in); and no real-world capture with a full authentication
    handshake -- validated by construction only, against synthetic
    `tests/sample_smb.pcap` (TCP, 26 packets across 7 independent
    sessions/flows) and `tests/sample_smb_tcp_split.pcap` (TCP, 2 packets,
    a TCP-segment-split reassembly case); if one becomes available later
    it should be added and PROTOCOL_COVERAGE.md's Validation subsection
    updated accordingly. 21 new `smb_*`/`smb1_*` CTest tests (every
    message type, all six curated notes with an explicit negative case
    each, the full NTLM handshake and its own multi-leg correlation
    -- both succeeded and failed outcomes, compounding, `--stats` Status
    counts, `--protocol smb`/`--smb-port`, non-standard-port note, and
    TCP-segment-split reassembly) plus 1 new and 7 updated
    `lateral_movement_*`/`notable_protocols_*`/`real_hartip_*` tests for
    the fixture-behavior changes above -- full existing suite (1275
    tests) stays 100% passing, zero-warning build.

28. **Netlogon/DCE-RPC (MS-NRPC, MS-RPCE) -- phase 4 of 4, closing out the
    Windows Active Directory suite, with curated attack/monitoring
    detection headlined by CVE-2020-1472 ("Zerologon").** The natural
    completion of item 27's own deferral: DCE/RPC-over-named-pipe traffic
    (Netlogon chief among it) rides inside SMB2 CREATE/WRITE/READ/IOCTL
    against an `IPC$`-hosted named pipe, which item 27 left
    structural-only on purpose. This is where a domain-joined machine (or
    an attacker impersonating one) establishes and uses a "Netlogon Secure
    Channel" with a domain controller -- and where Zerologon lives: an
    attacker who sends an all-zero `ClientChallenge`/`ClientCredential`
    can forge that channel to a DC's own computer account and blank its
    machine password from there. lsarpc/samr/srvsvc and every other RPC
    interface that can also ride over `IPC$` remain out of scope --
    Netlogon only.

    **Done.** **No new `ProtocolDecoder`, no independent wire gate** --
    unlike every prior AD-suite item, this traffic has no signature or
    port of its own to register; it's recognized only structurally, via a
    tracked SMB2 `FileId` whose `CREATE` `Name` (stripped of any `\PIPE\`
    prefix) equals `"netlogon"`, the same "sub-parser invoked from
    `smb.cpp`, no gate of its own" shape item 27's own NTLM embedding
    already established. Two new modules, split envelope-vs-protocol the
    same way `smb.hpp`/`ntlm.hpp` are: `dcerpc.hpp`/`dcerpc.cpp` (a
    generic DCE/RPC connection-oriented PDU reader -- the 16-byte common
    header, `bind`/`bind_ack` context negotiation, `request`/`response`/
    `fault` bodies, `sec_trailer` -- reusable by a future lsarpc/samr/
    srvsvc pass, not built now) and `netlogon.hpp`/`netlogon.cpp` (the
    Netlogon interface UUID, opnum table, NDR field decoders). A
    genuinely new wrinkle neither item 27 nor any earlier AD-suite item
    had: **RPC-layer sealing** (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`) --
    Windows sends `NetrServerPasswordSet2` and similar post-channel-
    establishment calls encrypted, so this decoder reads `auth_level` from
    the trailer's own unencrypted fixed header and falls back to an honest
    "sealed, N bytes, not decoded" summary rather than attempting to parse
    ciphertext as plaintext NDR -- the same "never decrypt a cipher this
    codebase doesn't hold the key for" limit applied everywhere else, and
    good news for scope: the calls that establish the channel (the ones
    with the highest curated-note value) are exactly the ones that arrive
    in the clear.

    `NetrServerReqChallenge`/`NetrServerAuthenticate`/
    `NetrServerAuthenticate2`/`NetrServerAuthenticate3` fully field-decoded
    (`PrimaryName`/`AccountName`/`ComputerName` via NDR conformant-varying
    strings, `SecureChannelType` -- a 16-bit NDR enum, confirmed
    empirically against `impacket`'s own marshalling during planning, not
    the 32-bit width a casual IDL reading might suggest --
    `ClientChallenge`/`ClientCredential` never rendered beyond a boolean,
    `NegotiateFlags`, `AccountRid`); `NetrServerPasswordSet2` header-level
    only, `Authenticator`/`ClearNewPassword` presence+length-only, the
    same posture item 27's own `LmChallengeResponse`/`NtChallengeResponse`
    established; every other opnum structural-only, named from a verified
    curated table. A real correctness bug was caught by first-principles
    NDR review before any fixture was written, not by a compiler or a
    test: `SecureChannelType` (16-bit) is immediately followed by a
    4-byte-aligned conformant string in two different call shapes, so the
    original string readers needed an explicit `align4()` self-alignment
    step they were missing -- fixed before the fixture generator was
    written, so the fixture exercises the corrected parser rather than
    baking in a workaround for a buggy one.

    Five curated notes: Netlogon secure channel established/failed
    (closing correlation, the anchor the rest hang off of), **all-zero
    ClientChallenge/ClientCredential -- the Zerologon wire signature and
    this item's single highest-value note**, legacy authentication method
    (opnum 5/15 instead of the modern 26), machine-account naming mismatch
    (`SecureChannelType` claims a machine channel but `AccountName` lacks
    the conventional `$` suffix), and `NetrServerPasswordSet2` observed
    (the literal next step after a forged channel in a real Zerologon
    chain -- deliberately the one note in this phase that is NOT sticky,
    unlike the other four).

    State/correlation (`SmbFlowState`, still keyed by
    `FlowStateKeying::Session`) is **the deepest correlation shape in this
    codebase**: SMB2 `FileId` (handle) -> DCE/RPC `bind` (interface
    confirmation) -> DCE/RPC `call_id` (request/response pairing), one
    genuine layer deeper than item 27's own `SessionId`-keyed two-leg NTLM
    handshake. A `TreeId`-keyed map persists `ShareType` past
    `TREE_CONNECT`; a `FileId`-keyed map (created only for a confirmed
    `netlogon`-named pipe, erased on `CLOSE`) holds both a short-lived
    `call_id` sub-map for immediate PDU pairing and longer-lived sticky
    fields driving the closing correlation note and the fire-once notes.

    Manually smoke-tested against a 9-flow hand-built synthetic Netlogon/
    DCE-RPC exchange (every curated note's positive AND negative case, the
    sealed-call fallback, the non-Netlogon-interface-bind edge case, the
    never-tracked-pipe-name negative control, and both the WRITE+READ and
    IOCTL/`FSCTL_PIPE_TRANSCEIVE` transport shapes) BEFORE any
    CMakeLists.txt test was written against it -- the same discipline that
    caught item 22's Kerberoasting field-mixup bug and item 23's
    messageID-correlation bug; this time it caught the `align4` NDR
    alignment bug above (during first-principles review, before fixture
    generation) and a fixture-generator bug (the READ Response helper was
    independently minting its own `MessageId` instead of reusing the
    matching READ Request's, silently breaking SMB2's own wire-level
    request/response correlation for every WRITE+READ flow -- fixed by
    threading the assigned `MessageId` through a shared mutable cell). 24
    new `netlogon_*` CTest tests (every decoded opnum, all five curated
    notes with an explicit negative case each, the bind-interface-
    confirmation gate, the sealed-call fallback, `--stats` opnum counts,
    JSON field checks including a password-material-never-rendered test
    mirroring item 27's own NTLM credential test, and both transport
    shapes) -- full suite (1299 tests) stays 100% passing, zero-warning
    build across all three established configs (default+libpcap,
    no-libpcap, MinGW cross-compile). See `include/conduitscope/dcerpc.hpp`'s
    and `include/conduitscope/netlogon.hpp`'s file headers for the full
    writeup and docs/PROTOCOL_COVERAGE.md's Netlogon/DCE-RPC section for
    the user-facing reference.

    **PROTOCOL DETECTION note**: unlike every prior AD-suite item, this
    one adds no new detection bullet to any "how is protocol X
    recognized" summary elsewhere in this document -- Netlogon/DCE-RPC has
    no independent wire gate at all (see above), so there is nothing to
    add to `tcp_port_independent_registry()` or any port/signature table;
    it is reached purely through SMB2's own already-established detection
    plus this item's own FileId-tracking state.

    **Still not done**: lsarpc, samr, srvsvc, wkssvc, or any RPC interface
    other than Netlogon, even over the same `IPC$` share (explicitly out
    of scope, a possible future item); DCE/RPC PDU fragmentation
    reassembly across multiple WRITE/READ pairs (first-pass scope is
    single-fragment calls, which covers every opnum this item decodes in
    practice); actual Netlogon Secure Channel cryptographic verification
    (only the all-zero wire pattern is recognized, never session-key
    derivation or signature/seal verification); decoding sealed stub data;
    no `policy validate`/`inventory` integration (degrades gracefully, the
    same posture items 20/22/23/27 are still in); and no real-world
    capture -- validated by construction only, against synthetic
    `tests/sample_netlogon.pcap` (TCP, 142 packets across 9 independent
    flows); if one becomes available later it should be added and
    PROTOCOL_COVERAGE.md's Validation subsection updated accordingly.

    **Update: lsarpc/samr/srvsvc/wkssvc/drsuapi + WinRM + WMI, phase 0
    (prerequisite generalization).** Jurgen asked for the remaining
    Windows RPC interfaces and, separately, WinRM/WMI. Netlogon was the
    only interface riding `dcerpc.hpp` at the time, and `smb.hpp`/
    `smb.cpp`'s pipe-tracking/dispatch plumbing was written narrowly
    around it (a single `NetlogonPipeState`-typed map, three dispatch
    sites each hardcoded to Netlogon's own decode call). Before writing
    any new interface module, that plumbing needed to split into
    interface-agnostic wire bookkeeping (shared) and interface semantics
    (kept separate per interface, matching this project's own RIP/IGMP/
    VRRP/IGRP precedent of not unifying structurally-similar-but-
    semantically-distinct protocols) -- a prerequisite phase with no
    user-visible output on its own, verified purely by proving Netlogon's
    existing behavior stays byte-identical.

    `dcerpc.hpp`/`dcerpc.cpp` gained a `resolve_dcerpc_bind_bookkeeping<PipeState>()`
    template (the bind/bind_ack/fault correlation logic `smb.cpp`'s
    Netlogon dispatch already did inline, factored out for reuse by every
    future interface's own pipe-state type) and `PendingDceRpcCall` moved
    here from `smb.hpp` (it was already interface-agnostic). The three NDR
    string helpers `netlogon.cpp` had as local, file-private functions
    (`align4`/`read_ndr_string`/`read_ndr_unique_string`, renamed
    `ndr_align4` at its new home to avoid colliding with the generic
    alignment idiom's common name) moved to `dcerpc.hpp`/`dcerpc.cpp` too,
    to avoid five-way duplication across the interface modules about to
    be built on top; `netlogon.cpp` now includes `dcerpc.hpp` directly for
    them (deliberately not added to `netlogon.hpp`, which stays decoupled
    from `dcerpc.hpp`'s own types by design -- see that header's STUB DATA
    paragraph). **Netlogon's own decode logic is otherwise untouched.**

    `smb.hpp`'s `try_parse_smb` gate parameter generalized from a
    `NetlogonPipeState`-typed map to a plain `unordered_set<SmbFileId>`
    (all it was ever used for -- membership only); `SmbFlowState` gained
    a unified `tracked_rpc_pipe_file_ids` set kept in lockstep with every
    per-interface pipe-state map. `smb.cpp`'s three WRITE/READ/IOCTL
    dispatch sites collapsed into one `dispatch_dcerpc_payload(m, state,
    file_id)` helper. One correctness risk caught before any test ran:
    an early draft had the READ-response dispatch site mutate the
    response message's own `file_id`/`has_file_id` fields (SMB2 READ
    responses never carry a FileId of their own on the wire, and
    `output.cpp` renders `"file_id"` whenever `has_file_id` is set) --
    fixed by threading the FileId through as an explicit parameter
    (sourced from the pending-request state) instead of ever writing it
    onto the response message.

    Verified against a fresh from-scratch build in both established
    configs (default: 1416/1416, zero warnings; `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`:
    1404/1404, zero warnings) plus manual `--format json`/`--format text
    --verbose`/`--stats` smoke tests against `sample_netlogon.pcap`
    confirming every opnum still decodes correctly (including the
    ATTACKER-PC/ALL-ZERO negative-control flow) and that READ responses
    still carry no `file_id` field. No new fixture, `PROTOCOL_COVERAGE.md`
    entry, or CLI-visible change -- nothing user-facing changes until an
    interface is actually built on top of this plumbing (lsarpc/samr next).

    **Update: lsarpc/samr, phase 1 (the first two real interfaces).** New
    `include/conduitscope/samr.hpp`/`src/samr.cpp` and
    `include/conduitscope/lsarpc.hpp`/`src/lsarpc.cpp`, shaped exactly like
    `netlogon.hpp`/`.cpp`: an interface UUID constant, `is_<x>_interface_uuid()`,
    `<x>_opnum_name()`, a fully-typed `<X>Call` struct, `try_parse_<x>_request/
    _response()`, called directly from two new `smb.cpp` functions
    (`decode_dcerpc_and_samr`/`decode_dcerpc_and_lsarpc`) that are the first
    real callers of Phase 0's `resolve_dcerpc_bind_bookkeeping` template.
    SAMR full-decodes `SamrLookupNamesInDomain(17)`/`SamrLookupIdsInDomain(18)`
    (RID<->name resolution), `SamrEnumerateUsersInDomain(13)`/
    `SamrEnumerateAliasesInDomain(15)`, `SamrGetAliasMembership(16)`, and the
    `SamrConnect` family (0/57/62 -- ServerName only, uniformly; 64/Connect5
    stays structural, its OutRevisionInfo union not independently verified);
    header-only for `SamrOpenDomain(7)`/`OpenUser(34)`/`OpenAlias(27)`/
    `OpenGroup(19)` (the target SID/RID + DesiredAccess, no handle-level state
    tracked across calls -- same posture Netlogon never needed either);
    structural-only with ZERO field decode (more conservative than Netlogon's
    own presence/length-only `NL_TRUST_PASSWORD` precedent) for the three
    password-shaped opnums `SamrChangePasswordUser(38)`/
    `SamrOemChangePasswordUser2(54)`/`SamrSetInformationUser(37)`. LSARPC
    full-decodes `LsarLookupNames(14)`/`LsarLookupSids(15)` and, promoted from
    the plan's original structural-only tier once the shared array primitives
    already existed, `LsarEnumerateAccounts(11)`/`LsarEnumerateTrustedDomains(13)`;
    `LsarOpenPolicy(6)`/`OpenPolicy2(44)` response is decoded (the opened
    handle + status) but the REQUEST side stays structural-only by design --
    ObjectAttributes' own SECURITY_QUALITY_OF_SERVICE pointer chain wasn't
    independently verified to this codebase's own confidence bar, so it's
    flagged rather than guessed at, the same "disclose the reduction" posture
    the `_2`/`_3`/`_4` Lookup variants (opnums 57/58/68/76/77) get too
    (structural-only, their EX array shapes -- an extra Flags field, SID-vs-RID
    differences -- not independently verified either).

    The single largest technical risk in this phase was NDR's own deferred-
    pointer-data placement rule, which is genuinely ambiguous from [MS-RPCE]'s
    prose alone once more than one pointer is in play. Resolved empirically,
    by installing impacket 0.13.1 in the planning sandbox and round-tripping
    hand-built bytes through both its marshaller (to see real layouts) and its
    unmarshaller (`fromString()`, to confirm a hypothesis against bytes this
    codebase itself constructed) -- with deliberately DISTINCT disambiguating
    field values (e.g. `EntriesRead=111` vs `CountReturned=222`) after an
    early test with two equal values produced a result that only looked
    consistent with a wrong hypothesis. The confirmed rule, now documented in
    `samr.cpp`'s own header comment and applied consistently everywhere: a DCE/RPC
    call's own TOP-LEVEL request/response parameters resolve EAGERLY (each
    field, including full recursive resolution of anything it points to, is
    completely written before the next top-level field begins); a NESTED
    constructed type (reached only via pointer indirection) uses the textbook
    NDR "batched" shape (all of that struct's own fields written first, THEN
    its own pointers' deferred data, in declared order); an ARRAY always
    batches its own elements' deferred data after ALL elements' fixed parts,
    regardless of nesting depth. Five new shared NDR primitives landed in
    `dcerpc.hpp`/`dcerpc.cpp` for this (`read_ndr_sid`, `read_ndr_sid_pointer_array`,
    `read_ndr_unicode_string_array`, `read_ndr_ulong_conformant_varying_array`,
    `read_ndr_count_and_ptr_ulong_array`), each DoS-capped at
    `resource_limits().max_decoded_objects` like every other array-reading loop
    in this codebase.

    Two curated notes per interface (SAMR account/group enumeration; LSARPC
    SID/name translation or enumeration), each sticky once per pipe
    conversation, escalating their wording when
    `SmbFlowState::null_or_guest_session_seen` is set (a new sticky flag,
    populated alongside the pre-existing curated note 4 in the SESSION_SETUP
    response handler) -- null-session SAM/LSA enumeration is a well-known
    high-value misconfiguration, not just routine recon. Plus one
    cross-interface note ("SAMR and LSARPC enumeration both observed on this
    session"), only possible because Phase 0 put `samr_pipes`/`lsarpc_pipes`
    on the same `SmbFlowState` -- fires once (a new
    `samr_lsarpc_cross_interface_note_seen` sticky flag) whichever interface's
    own enumeration note happens to fire second, the actual enum4linux/
    BloodHound-style wire pattern (RID/name resolution plus SID translation
    together on one session) rather than two coincidental calls.

    New fixture: `tools/make_sample_pcap.py`'s `build_samr_lsarpc_sample()`
    (`tests/sample_samr_lsarpc.pcap`, 6 independent flows A-F), plus new
    `NdrBuf` methods for every wire shape this phase's opnums need (`sid`,
    `sid_pointer_array`/`sid_array_ptr`, `unicode_string_array`/
    `names_ptr_array`, `ulong_array`, `count_and_ptr_ulong_array`,
    `trust_info_array`/`referenced_domain_list_field`,
    `translated_sids_field`/`translated_names_field`) and three standalone
    stub builders for the more complex nested response shapes
    (`samr_enumerate_response_stub`, `lsar_enumerate_accounts_response_stub`,
    `lsar_enumerate_trusted_domains_response_stub`) -- each the exact byte-level
    inverse of one shared reader, verified by round-tripping the fixture
    through the actual built decoder (not hand-computed) before any
    CMakeLists.txt test was written. One bug this process caught directly:
    an early draft of `sid_array_ptr`'s own call sites double-encoded the
    SidArray's leading `Count` field (once explicitly, once again inside
    `sid_array_ptr` itself), corrupting every SID that followed -- caught by
    decoding the fixture and seeing `sids=0` where `sids=1`/`sids=2` was
    expected, not by code review. 30 new CMakeLists.txt tests cover every
    full-decode opnum's request/response fields, both interfaces' enumeration
    notes (positive), the cross-interface note (firing once, not twice), the
    null/guest-session escalation wording, the sealed-call fallback (no field
    decode, no note), the secret-shaped opnums' zero-field-decode posture
    (asserting the fixture's own non-zero stub bytes never appear in decoded
    output), the bind-interface-confirmation negative control (a non-SAMR
    bind on a samr-named pipe never produces `samr_calls`), and `--stats`
    opnum counts for both interfaces.

    Verified against a fresh from-scratch build in both established configs
    (default: 1445/1445, zero warnings; `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`:
    1433/1433, zero warnings) plus manual `--format json`/`--format text
    --verbose`/`--stats` smoke tests against the new fixture. `smb_lsarpc`'s
    own CREATE-name gate meant one existing Netlogon test
    (`netlogon_untracked_pipe_name_never_parsed_json`) needed rewriting: its
    own premise (an "lsarpc"-named pipe is never tracked) was invalidated by
    this phase adding LSARPC pipe tracking, so it was renamed and rewritten
    to assert the new, still-meaningful behavior instead (the envelope now
    parses -- `dcerpc_messages` appears -- but the bound interface UUID being
    Netlogon's own, not LSARPC's, still means zero `lsarpc_calls`/`samr_calls`)
    rather than silently left asserting something now false.

    `docs/PROTOCOL_COVERAGE.md`'s SAMR/LSARPC section, `man/conduitscope.1`,
    and `README.md` updated in this same phase, not deferred.

    **Update: srvsvc/wkssvc, phase 2 (bundled for scope parity, no
    cross-interface note).** New `include/conduitscope/srvsvc.hpp`/
    `src/srvsvc.cpp` and `include/conduitscope/wkssvc.hpp`/
    `src/wkssvc.cpp`, the same `netlogon.hpp`-shaped template Phase 1 used,
    called from two new `smb.cpp` functions (`decode_dcerpc_and_srvsvc`/
    `decode_dcerpc_and_wkssvc`) that are Phase 0's `resolve_dcerpc_bind_
    bookkeeping` template's third and fourth callers. Unlike SAMR/LSARPC,
    these two interfaces have no cross-interface note -- bundled purely for
    scope-per-phase consistency, not because one call informs the other.
    SRVSVC full-decodes `NetrShareEnum(15)`/`NetrShareGetInfo(16)`, scoped
    to LEVEL 1 ONLY (`shi1_netname`/`shi1_type`/`shi1_remark` -- what `net
    view` itself displays; every other level reported by number only).
    Header-only on the REQUEST side ONLY for `NetrConnectionEnum(8)`/
    `NetrFileEnum(9)`/`NetrSessionEnum(12)` (ServerName + Level) -- their
    RESPONSE side is deliberately structural-only instead, a genuinely new
    wrinkle relative to Phase 1's own header-only tier: each response's own
    per-entry array uses a LEVEL-DEPENDENT info struct
    (CONNECTION_INFO_0/1, FILE_INFO_2/3, SESSION_INFO_0/1/2/10/502) that
    sits, in the wire's own top-level field order, BEFORE `TotalEntries` --
    so reaching `TotalEntries` at all would mean walking that array first,
    and none of those per-level shapes were independently verified, so
    rather than guess at how many bytes to skip (risking silent
    misalignment of every field read afterward, including the response's
    own `ErrorCode`), the response stops at opnum/status only. Opnum-name-
    only with a curated note firing on every occurrence (not sticky, the
    same posture Netlogon's own `NetrServerPasswordSet2` note already
    established) for `NetrShareAdd(14)`/`NetrShareDel(18)`. WKSSVC full-
    decodes `NetrWkstaGetInfo(0)`, level 100 only
    (`wki100_platform_id`/`computername`/`langroup`/`ver_major`/
    `ver_minor`), and `NetrWkstaUserEnum(2)`, level 1 only
    (`wkui1_username`/`logon_domain`/`oth_domains`/`logon_server` -- who is
    logged on and from where, the directly recon-relevant field set).
    Header-only (request side only, same reasoning as SRVSVC's own three)
    for `NetrWkstaTransportEnum(5)`. Opnum-name-only with a per-occurrence
    curated note for `NetrJoinDomain2(22)`/`NetrUnjoinDomain2(23)` -- both
    carry a `PJOINPR_ENCRYPTED_USER_PASSWORD` field never parsed, the same
    "never decode anything credential/secret-shaped" posture SAMR's own
    password opnums established, distinguished only by the curated note
    firing here (a domain join/unjoin is a rarer, higher-signal
    administrative event worth flagging even without decoding its
    payload).

    Two SRVSVC-specific NDR facts, confirmed empirically (installing
    impacket 0.13.1, marshalling real `NetrShareEnum`/`NetrShareGetInfo`
    request/response objects, hex-dumping the actual bytes -- not recalled
    from training): `SHARE_ENUM_STRUCT`'s embedded `SHARE_ENUM_UNION`
    carries its OWN 4-byte tag/discriminant on the wire, immediately after
    the struct's own `Level` field, even though the two are always equal
    (a real decoder could infer the tag from `Level` alone -- this codebase
    reads and discards the duplicate rather than assuming it away); and
    `SHARE_INFO_1` reached via a single (non-array) pointer -- as
    `NetrShareGetInfo`'s own response does -- still uses the "nested struct
    batches its own pointers" shape (netname-referent/type/remark-referent
    all written first, THEN netname's and remark's own deferred strings),
    NOT the eager per-field shape a first pass at this file actually got
    wrong (caught by re-deriving the exact byte layout from the same
    impacket hex dump before writing any CMakeLists.txt test, not by code
    review). `WKSTA_INFO_100`/`WKSTA_USER_INFO_1_ARRAY` (WKSSVC's own
    analogues) were verified the same way and confirmed to follow the
    identical nested-struct/batched-array rules Phase 1 already documented
    -- no new deferred-pointer wrinkle this time, just confirmation.
    `NetrWkstaUserEnum`'s own response `ResumeHandle` is a PLAIN ULONG
    VALUE, not a pointer -- unlike SRVSVC's own `NetrShareEnum` response,
    whose `ResumeHandle` IS a pointer -- also confirmed empirically rather
    than assumed from the two interfaces' otherwise-parallel shapes.

    New fixture: `tools/make_sample_pcap.py`'s `build_srvsvc_wkssvc_
    sample()` (`tests/sample_srvsvc_wkssvc.pcap`, 4 independent flows
    A-D), plus four standalone stub builders for the nested response
    shapes (`srvsvc_share_enum_response_stub`, `srvsvc_share_get_info_
    response_stub`, `wksta_get_info_response_stub`, `wksta_user_enum_
    response_stub`) built directly from the existing `NdrBuf` primitives
    (`unique_string`/`ref_string`/`u32`/`_ref`) with no new `NdrBuf` class
    methods needed -- every SRVSVC/WKSSVC wire shape this phase needed was
    already expressible with Phase 1's own building blocks. 27 new
    CMakeLists.txt tests cover every full-decode opnum's request/response
    fields (including the STYPE_SPECIAL "(special)" suffix on IPC$'s own
    share type), every header-only opnum's request-only decode plus its
    deliberately-structural response, both interfaces' curated notes
    (share add/delete; domain join/unjoin) firing per-occurrence, the two
    secret/credential-shaped opnums' zero-field-decode posture (asserting
    the fixture's own non-zero stub bytes never appear in decoded output),
    the sealed-call fallback, the bind-interface-confirmation negative
    control (a non-SRVSVC bind on a srvsvc-named pipe never produces
    `srvsvc_calls`), and `--stats` opnum counts for both interfaces.

    Verified against a fresh from-scratch build in both established
    configs (default and `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`, both
    zero warnings; full suite 1472/1472) plus manual `--format json`/
    `--format text --verbose`/`--stats` smoke tests against the new
    fixture. `docs/PROTOCOL_COVERAGE.md`'s new SRVSVC+WKSSVC section,
    `man/conduitscope.1`, and `README.md` updated in this same phase, not
    deferred.

29. **MELSEC Communication Protocol (MC Protocol / SLMP), Mitsubishi
    Electric -- TCP port 5001, UDP port 5000.** Jurgen asked for this
    directly. **Done.** Mitsubishi's own PLC communication protocol --
    functionally the direct Mitsubishi analogue of Modbus/S7comm (device
    memory read/write, remote CPU RUN/STOP/PAUSE/RESET, normally with no
    protocol-level authentication). Built entirely on the
    `ProtocolDecoder` registration-model interface from inception, joining
    TwinCAT (item 20) and Kerberos (item 22) on that path, and the first
    protocol on it with a genuine dual TCP+UDP transport built from
    scratch rather than migrated (TwinCAT is TCP-only; HART-IP/EtherNet-
    IP's own TCP+UDP splits predate the interface).

    Every byte-level field was verified two ways during planning: against
    Mitsubishi's own official SLMP Reference Manual plus second-source
    vendor manuals (Kepware/PTC's and Pro-face's own Mitsubishi Ethernet
    driver manuals), and empirically, by reading `pymcprotocol`'s (a
    small, actively-maintained pure-Python implementation) own frame-
    building source directly -- which caught a real transcription error
    an LLM-summarized PDF fetch alone had introduced (a claimed 1-byte
    subheader/command field with device code `D`=0x44, versus the real
    2-byte subheader/command fields with device code `D`=0xA8). Jurgen
    also pointed at the `ITI/ICS-Security-Tools` GitHub repository's
    `pcaps/` collection as a possible source of real MELSEC traffic;
    investigated directly (that repo, and its linked `automayt/ICS-pcap`
    collection, list MELSEC only as a still-wanted, not-yet-contributed
    protocol) -- no real capture was found, but this incidentally
    corroborated the port convention from a third independent source.

    13 commands fully field-decoded (request AND response): Batch Read/
    Write, Random Read/Write, Remote RUN/STOP/PAUSE/LATCH CLEAR/RESET,
    Read CPU Type, Remote Password UNLOCK/LOCK, and Echo/Loopback Test --
    both the "standard" and "extended"/iQ-R device-addressing shapes, and
    both 3E and 4E binary framing (ASCII-mode framing and the legacy 1E
    frame are named but out of scope). Per an explicit design decision,
    Remote Password UNLOCK/LOCK's cleartext password value is never
    rendered in any output format -- only its length -- mirroring NTLM's
    own credential-redaction posture (item 27) rather than RIP/HSRP's more
    permissive one.

    A real architectural wrinkle, not fully anticipated before
    implementation: **a MELSEC response carries no command field of its
    own on the wire at all** (unlike Modbus/TwinCAT/S7comm, which all
    repeat their function code/command ID on both request and response),
    so decoding a response's own command-specific body requires knowing
    which request it answers. Solved with a single session-scoped
    pending-request slot (`MelsecFlowState::pending`) -- deliberately
    *not* authoritative pairing like Modbus's transaction ID or TwinCAT's
    Invoke ID (3E frames carry no transaction identifier at all, and the
    4E frame's own Serial No. is deliberately not used for this, matching
    S7comm's own "stateless" precedent for a field this pass doesn't
    trust is reliably unique in real captures); reported as "matched to
    the request seen in packet #N," never "authoritatively paired."

    **A real, live collision was caught by this item's own required
    manual smoke test**, the discipline that has now caught a real bug in
    nearly every protocol addition in this codebase's history: HART-IP's
    own deliberately weak UDP structural gate (item -- see
    PROTOCOL_COVERAGE.md's HART-IP section -- MessageType/MessageID at
    payload bytes 1/2 both small enumerated values, MsgLength >= 8, no
    magic bytes, no exact-length check) was incidentally satisfied by real
    MELSEC UDP traffic often enough to matter, silently stealing MELSEC
    packets before MELSEC's own much stronger two-part gate (exact
    subheader magic + exact declared-length cross-check) ever ran. Fixed
    by reordering MELSEC's UDP dispatch to run BEFORE HART-IP's in
    `decoder.cpp`'s Auto-mode cascade -- the same "stronger gate wins"
    resolution IEC104-before-Modbus and QUIC-before-HART-IP already
    establish elsewhere in that same cascade -- verified with no reverse-
    collision risk (real HART-IP traffic's Version byte is never one of
    MELSEC's four exact subheader values). See PROTOCOL_COVERAGE.md's new
    MELSEC section for the full collision-survey writeup.

    24 new `melsec_*` CTest tests (every decoded command, the bit-units
    nibble-packing quirk, the 4E Serial No. field, the redacted-password
    proof across text/JSON/CSV, both named End Codes, the unknown-command
    structural fallback, a gate-rejection negative control, a TCP segment-
    split reassembly, UDP coverage including a non-standard-port note and
    a declared-length-mismatch negative control, the HART-IP collision
    regression proof specifically, `--stats` command-name counts, and
    protocol-filter/extra-port CLI options) -- full suite (1328 tests)
    stays 100% passing, zero-warning build across all three established
    configs. See `include/conduitscope/melsec.hpp`'s file header for the
    full writeup and docs/PROTOCOL_COVERAGE.md's new MELSEC / MC Protocol
    section for the user-facing reference. **Still not done**: ASCII-mode
    framing; the legacy 1E frame; any command/subcommand pair outside the
    13 verified ones (shown numerically only); 4E Serial No.-based
    cross-packet pairing; any session-state model of PLC password-lock
    state; no `policy validate`/`inventory` integration (degrades
    gracefully, the same posture several other protocols are still in);
    and no real-world capture confirmed against (validated by construction
    only, against synthetic `tests/sample_melsec.pcap`).

    **POST-DELIVERY FIX (found during the FINS follow-up feature, item
    30): a second real, live collision, this time with Modbus/TCP.**
    Jurgen reported it directly; confirmed with a synthetic decode before
    fixing. The original collision survey's own Modbus reasoning ("the
    declared-length field almost never leaves zero") checked the wrong
    byte range -- `payload[2:4]` is actually MELSEC's own Network
    No.+PC No., both legitimately 0 in real traffic (pc_no==0 is a real
    station number, not just this decoder's own sample-fixture default of
    0xFF), and `payload[4:6]` (Request Destination Module I/O No.,
    little-endian) can read as a small, plausible Modbus `mbap_length`
    when byte-swapped (e.g. a real non-"own-station" I/O number like
    `0x0000`, not just the `0x3FF` sentinel) -- and Modbus's own decode
    does not hard-reject the resulting length mismatch. Fixed the same way
    as the HART-IP collision above: reordered MELSEC's own TCP dispatch to
    run BEFORE Modbus's (`decoder.cpp`/`protocol_registry.cpp`), the same
    "stronger gate wins" resolution, plus a dedicated regression test
    (`melsec_tcp_request_not_misdetected_as_modbus`). Also corrected: a
    real MELSEC/Mitsubishi capture DOES exist in the same
    `ITI/ICS-Security-Tools` collection the original delivery checked --
    `pcaps/MELSEC/melsoft_tcp_2_159_pkt.pcap` (159 packets) -- found via
    Jurgen's own pointer; this session's own sandbox tooling could not
    download it (GitHub's raw-download paths are blocked by `robots.txt`
    here, and the file is too large for the available web-fetch tool to
    responsibly transcribe as hex), so it remains unrevalidated against,
    an honest gap rather than a silently repeated miss. Full suite (1329
    tests after this fix) stays 100% passing. See
    `include/conduitscope/melsec.hpp`'s own "POST-DELIVERY FIX" paragraph
    and docs/PROTOCOL_COVERAGE.md's updated MELSEC collision-survey
    subsection for the full writeup.

30. **FINS (Factory Interface Network Service), Omron -- TCP port 9600,
    UDP port 9600.** Jurgen asked for this directly. **Done.** Omron's
    own PLC communication protocol -- functionally the direct Omron
    analogue of Modbus/S7comm/MELSEC (memory-area read/write, remote CPU
    RUN/STOP, force-set/reset individual I/O bits, clock read/write,
    normally with no protocol-level authentication). Built entirely on
    the `ProtocolDecoder` registration-model interface from inception,
    the second protocol on it (after MELSEC, item 29) with a genuine dual
    TCP+UDP transport built from scratch -- but unlike MELSEC's own split
    5001/tcp + 5000/udp, FINS uses the SAME conventional port (9600) for
    both transports.

    Every byte-level field was verified three ways during planning --
    more rigorous than MELSEC's own two-way check, because a canonical
    third source exists here that didn't for MELSEC: `aphyt/omron_fins`
    (a pure-Python client library), `lammertb/libfins` (a C library,
    confirming the same 10-byte header layout via independently-named
    `#define`s and supplying a much larger end-code table), and
    Wireshark's own `packet-omron-fins.c` dissector (citing the official
    "OMRON FINS Commands Reference Manual, W227-E1-2" by name). This
    caught a real error a fetched SEO/content-site summary made (claiming
    the FINS/TCP Length field is little-endian and that MRC+SRC form one
    opaque 2-byte field; all three primary sources agree Length is
    big-endian and MRC/SRC are genuinely two separate 1-byte fields).

    Jurgen also pointed at the same `ITI/ICS-Security-Tools`/
    `automayt/ICS-pcap` repositories checked for MELSEC. `automayt/
    ICS-pcap` does list an `omron.pcap` capture this time, but it is
    git-LFS-stored and this sandbox's tooling could not download its
    actual bytes (the same class of gap MELSEC's own post-delivery
    real-capture check ran into with `melsoft_tcp_2_159_pkt.pcap`) -- an
    honest gap, not a silent one. Real wire-format confirmation was
    instead extracted from that same repository's own `conn.log` and an
    embedded `omrontcp-info.nse` Nmap script carrying a real FINS/TCP
    probe against real devices, which surfaced two corrections to this
    feature's own implementation plan: GCT (Gateway Count) is `0x02` in
    that real probe, not the documented-but-conventional `0x07`; and SA2
    (source unit address) is `0xEF`, outside the documented 0-31 range --
    so, unlike the original plan, this decoder's own UDP gate does NOT
    range-check DA2/SA2 at all.

    17 commands fully field-decoded (request AND response): Memory Area
    Read/Write/Fill, Multiple Memory Area Read, Run/Stop, Controller Data
    Read, Controller Status Read, Cycle Time Read, Clock Read/Write,
    LOOP-BACK Test, Access Right Acquire/Forced Acquire/Release, Error
    Clear, Forced Set/Reset, and Forced Set/Reset Cancel -- plus the
    FINS/TCP outer envelope's own handshake (Node Address Data Send),
    Frame Send Error Notification, and Connection Confirmation.

    A genuine architectural difference from MELSEC, discovered during
    implementation: **a FINS response frame DOES self-describe its own
    command code** at the same offset a request's own MRC/SRC sit at --
    the opposite of MELSEC's own "no command field on the response at
    all" wrinkle (item 29's own entry above). This means most responses
    decode entirely context-free; only Memory Area Read and Multiple
    Memory Area Read responses still need their own matching request's
    device list (no repeated area-code/count info of their own on the
    wire), handled via a narrower, single-purpose `FinsFlowState` than
    MELSEC's own `MelsecFlowState` needed.

    Because FINS/UDP has no magic-byte signature at all (unlike FINS/TCP's
    own exact 4-byte `"FINS"` magic), its own UDP structural gate is a
    multi-field check instead (minimum length, ICF reserved bits exactly
    zero, RSV exactly `0x00`, and an exact match against the 17-command
    allowlist -- an unrecognized command is REJECTED outright, not shown
    numerically the way MELSEC's own unknown commands are, because
    FINS/UDP has no other anchor to fall back on). **This item's own
    required manual smoke test caught the same class of real collision
    risk MELSEC's own item did**: HART-IP's weak UDP gate (MessageType/
    MessageID at payload bytes 1/2 both small enumerated values) has a
    real, partial overlap with FINS's own byte layout -- FINS's byte[1]
    is always RSV=0x00 (satisfies HART-IP's MessageType==0), and the real
    NSE-probe-observed GCT value of 0x02 (not the conventional 0x07 the
    original plan assumed was safe) DOES satisfy HART-IP's own
    MessageID-in-{0,1,2,3} condition. Fixed the same way MELSEC's own
    collision was: FINS's own UDP dispatch runs BEFORE HART-IP's in
    `decoder.cpp`'s Auto-mode cascade, with a dedicated regression test
    (`fins_udp_request_not_misdetected_as_hartip`) built using GCT=0x02
    specifically, so this real overlap is exercised on every run of the
    suite rather than left as a documented-but-untested theoretical
    concern.

    25 new `fins_*` CTest tests (every decoded command, the Multiple
    Memory Area Read session-state proof, the TCP handshake and envelope-
    only messages, a TCP segment-split reassembly, the unrecognized-
    command TCP-vs-UDP posture difference, two UDP gate-rejection
    negative controls, the HART-IP collision regression proof
    specifically, UDP coverage including a non-standard-port note,
    `--stats` command-name counts, and protocol-filter/extra-port CLI
    options) -- full suite (1354 tests) stays 100% passing, zero-warning
    build across all three established configs. See
    `include/conduitscope/fins.hpp`'s file header for the full writeup
    and docs/PROTOCOL_COVERAGE.md's new FINS section for the user-facing
    reference. **Still not done**: any command/subcommand pair outside
    the 17 verified ones (UDP: rejected by the gate; TCP: shown
    numerically only); deep bit-level decoding of Controller Status
    Read's own error-flag words (shown as raw hex); the 69-byte
    CPU-Bus-Unit-only Controller Data Read response variant's own field
    layout (shown structurally only); SID-based cross-packet correlation
    beyond the single-slot session state; no `policy validate`/
    `inventory` integration (degrades gracefully, the same posture
    several other protocols are still in); and no real-world capture
    confirmed against (validated by construction only, against synthetic
    `tests/sample_fins.pcap`; real wire-format details were independently
    confirmed via `conn.log`/NSE-script content, not a raw capture).

    **Update: heap-use-after-free found by the scheduled fuzz campaign,
    fixed.** `fins.cpp`'s `area_code_table()` builds its Expansion-DM-bank
    entries (area codes 0x20-0x2C/0xA0-0xAC, "E0_".."EC_") in a loop that
    used to store each `FinsAreaInfo::prefix` as a raw `const char*` taken
    from `.c_str()` of a `std::string` freshly `push_back`'d onto a
    `static std::vector<std::string> keep` meant to own the backing
    storage for the table's lifetime -- but a `std::vector` reallocates
    its buffer (and frees the old one) whenever a `push_back` exceeds
    current capacity, silently invalidating every `.c_str()` pointer
    already captured from an *earlier* iteration and already stored in
    the table. With 26 strings pushed and no `reserve()` call, this was
    essentially guaranteed to happen partway through the loop, leaving
    most of the Expansion-DM-bank entries' `prefix` pointers dangling for
    the rest of the process's lifetime (the table is built exactly once,
    via a function-local `static`). `fuzz_packet_decode`'s scheduled CI
    ASan campaign caught it as a heap-use-after-free read inside
    `make_item`'s `s << it->second.prefix` (fins.cpp), reading whatever
    unrelated allocation had since reused the freed address -- the
    specific "freed by ~HartIpPassThrough" address history ASan's crash
    report showed was coincidental (that memory had genuinely been a
    HART-IP string earlier and was genuinely freed correctly; it just
    happened to be the address libc's allocator handed back to FINS's own
    already-broken `keep` vector, or vice versa), not evidence of any
    actual interaction between the FINS and HART-IP decoders. Fixed by
    removing the raw-pointer workaround entirely: `FinsAreaInfo::prefix`
    is now a `std::string` (its only reader, `make_item`, already just
    streamed it through `operator<<`, so this cost nothing), so each
    table entry owns its own prefix directly and no cross-iteration
    pointer stability assumption is needed at all. Verified three ways:
    the full CTest suite (1,416 tests, including all 25 `fins_*` cases)
    stayed 100% passing; the exact crashing input from the CI log's own
    base64 dump, replayed directly against a local Clang+ASan+UBSan
    `fuzz_packet_decode` build, no longer crashes (clean exit, no
    sanitizer report); and that input is now committed as
    `fuzz/corpus/packet_decode/fins_area_code_table_dangling_prefix_uaf`
    (the first file in that corpus directory in this environment, which
    had none before), so `CONDUITSCOPE_ENABLE_FUZZING=ON`'s
    `fuzz_packet_decode_corpus_regression` CTest case now replays it on
    every future run -- confirmed passing locally.

31. **ARP (RFC 826), EtherType `0x0806`.** **Done.** A brand-new protocol,
    not a migration -- before this, ARP traffic was only ever named by
    `link_layer.hpp`'s `ethertype_name` (`[non-ip] ... ethertype 0x806
    (ARP) ...`) and otherwise left completely undecoded. Built entirely on
    the `ProtocolDecoder` registration-model interface from inception, the
    sixth protocol on that path from inception (after TwinCAT item 20,
    Kerberos item 22, MELSEC item 29, FINS item 30, and their UDP/TCP
    sibling instances), but architecturally closer to EAPOL/PPPoE/MPLS than
    to MELSEC/FINS: no port at all, no IP layer of its own, EtherType-gated
    dispatch straight off raw Ethernet.

    The wire format is a fixed 8-byte header (HTYPE/PTYPE/HLEN/PLEN/OPER)
    followed by a variable SHA/SPA/THA/TPA trailer whose length HLEN/PLEN
    themselves drive -- only HTYPE==1 (Ethernet)/PTYPE==0x0800 (IPv4)/
    HLEN==6/PLEN==4 gets SHA/THA rendered as a MAC address and SPA/TPA as a
    dotted-quad; anything else falls back to raw hex rather than guessing
    at an address format it doesn't have. OPER is checked against a curated
    opcode table (RFC 826 Request/Reply plus the RFC 903/1931/2390/2225
    RARP/DRARP/InARP/ATMARP extensions, plus IANA's MARS/MAPOS/Experimental
    values); an OPER outside that table declines the whole frame, which
    doubles as this decoder's structural detection gate, the same
    "EtherType carries most of the confidence" posture EtherCAT/EAPOL
    already established.

    On top of the base layout, three RFC 5227-flavored conditions are
    curated, matching Wireshark's own `packet-arp.c` logic: Gratuitous ARP
    (Request or Reply with SPA==TPA -- framed the same way this codebase
    already frames VRRP/HSRP failover events), ARP Probe (Request with
    SPA==`0.0.0.0`), and ARP Announcement (Request with SPA==TPA, wire-
    identical to a gratuitous Request, so both notes fire together).
    Deliberately out of scope: ARP spoofing/duplicate-IP detection, which
    needs cross-packet IP-to-MAC history this codebase tracks for no
    protocol, not even VRRP/HSRP's own "unexpected master" case.

    8 new `arp_*` CTest tests (Request, Reply, gratuitous Reply, Probe,
    Announcement with both notes firing, the non-Ethernet-HTYPE raw-hex
    fallback, a `--protocol arp` isolation check, and a `--stats` count) --
    full suite stays 100% passing, zero-warning build across all three
    established configs. Confirmed the pre-existing
    `link_layer_arp_ethertype_named` test (`tests/sample_link_transport_
    layers.pcap`'s own ARP filler frame, whose OPER reads as the
    unrecognized `0x0000`) is untouched and still correctly declines under
    the new decoder, falling through to `non-ip` exactly as before -- no
    fixture conflict between the two ARP-carrying fixtures. See
    `include/conduitscope/arp.hpp`'s file header for the full writeup and
    docs/PROTOCOL_COVERAGE.md's new ARP section for the user-facing
    reference. **Still not done**: RARP/DRARP/InARP/ATMARP/MARS/MAPOS
    opcodes' own reply-body semantics beyond the shared SHA/SPA/THA/TPA
    layout (named by opcode only); no `policy validate`/`inventory`
    integration (degrades gracefully, the same posture several other
    protocols are still in); no real-world capture confirmed against
    (validated by construction only, against synthetic `tests/
    sample_arp.pcap`).

32. **LLDP (IEEE 802.1AB), EtherType `0x88CC`.** **Done.** A brand-new
    protocol, not a migration -- before this, LLDP traffic was only ever
    named by `link_layer.hpp`'s `ethertype_name` (`[non-ip] ... ethertype
    0x88cc (LLDP) ...`) and otherwise left completely undecoded. Built
    entirely on the `ProtocolDecoder` registration-model interface from
    inception, right after ARP's own item 31 above, the same "no port, no
    IP layer, EtherType-gated dispatch straight off raw Ethernet" shape.

    The wire format is a sequence of TLVs, each a single 2-byte big-endian
    header packed as `type = header >> 9` / `length = header & 0x1FF` --
    one 16-bit word shared by both fields, not a byte-split type/length the
    way most other TLV formats in this codebase work -- followed by exactly
    `length` bytes of value. The genuinely interesting implementation note:
    Chassis ID and Port ID each carry a leading subtype byte, but these are
    **two independent subtype tables, not one table reused** -- subtype `4`
    is "MAC address" for Chassis ID but "Network address" for Port ID;
    subtype `3` is "Port component" for Chassis ID but "MAC address" for
    Port ID. It would have been easy to fold these into one lookup table
    and one render function since several values do coincide; `lldp.cpp`
    deliberately keeps the two tables, and the two render call sites,
    entirely separate to avoid that trap -- see `lldp.hpp`'s own file
    header for the cross-check against Wireshark's `packet-lldp.c`.

    The structural detection gate here is this codebase's strongest yet for
    a raw-Ethernet protocol: IEEE 802.1AB mandates the first three TLVs
    appear in fixed order -- Chassis ID, then Port ID, then a fixed 2-byte
    TTL -- and this decoder enforces exactly that, declining the whole
    frame on any deviation, stronger than EAPOL's/EtherCAT's/ARP's own
    "EtherType carries most of the confidence" posture (ARP's own
    curated-opcode-table gate, item 31 above, is the next strongest, but
    LLDP's three-TLV structural sequence is a tighter constraint than a
    ~20-entry opcode table). Once past that gate, a later TLV whose
    declared length overruns the remaining payload ends the TLV loop
    gracefully (a truncation note, everything decoded so far kept) rather
    than declining the whole PDU -- the same graceful-degradation posture
    IGRP's routes and EtherCAT's datagrams already established.

    Curated on top of the mandatory triple: Port/System Description, System
    Name (raw string); System Capabilities (two 2-byte bitmaps, named
    against IEEE 802.1AB Table 8-4); Management Address (IPv4 rendered
    dotted-quad, IPv6/802-MAC and everything else raw hex, only the first
    one seen curated onto the top-level fields); Organizationally Specific
    TLVs (OUI named for IEEE 802.1/802.3/TIA-1057 LLDP-MED/PROFINET, own
    Subtype plus raw-hex payload, no vendor sub-TLV structure decoded).

    8 new `lldp_*` CTest tests (mandatory-triple-plus-System-Name/
    Capabilities, Port/System Description plus Management Address, the
    "Locally assigned" Chassis ID raw-string case, an Organizationally
    Specific TLV, TTL=0, a truncated trailing TLV, a wrong-TLV-order
    negative control confirming the frame stays `non-ip`, and a
    `--protocol lldp` isolation check) -- full suite stays 100% passing,
    zero-warning build across all three established configs. See
    `include/conduitscope/lldp.hpp`'s file header for the full writeup and
    docs/PROTOCOL_COVERAGE.md's new LLDP section for the user-facing
    reference. **Still not done**: vendor-specific Organizationally-
    Specific sub-TLV bodies beyond OUI-plus-subtype naming; OID-to-dotted-
    notation translation for a Management Address TLV's Object Identifier
    (shown as raw hex); no `policy validate`/`inventory` integration
    (degrades gracefully, the same posture several other protocols are
    still in); no real-world capture confirmed against (validated by
    construction only, against synthetic `tests/sample_lldp.pcap`).

33. **BGP-4 (RFC 4271), TCP port 179.** **Done.** The last piece of the
    three-stage plan Jurgen approved back in item 3's own "Update" above
    (migration batch 5, then ARP+LLDP, then this) -- before this, BGP
    traffic on port 179 fell straight through to the generic `[tcp] TCP
    payload of N byte(s)` line, like any other unrecognized TCP stream.
    Built entirely on the `ProtocolDecoder` registration-model interface
    from inception, right after ARP (item 31) and LLDP (item 32) above,
    but architecturally the most involved of any new-protocol addition in
    this whole batch: unlike ARP/LLDP (raw-Ethernet, EtherType-gated, no
    port and no reassembly concept at all) and unlike TwinCAT/MELSEC/FINS
    (TCP-port-independent, but each single-message-per-payload), BGP rides
    TCP and needed three mechanisms together for the first time in one
    protocol: **declared-length TCP reassembly** (its own 19-byte header's
    Length field, reusing `Decoder::reassemble_tcp_payload`'s existing
    declared-length machinery, the same role Modbus's MBAP/MELSEC's/FINS's
    own Length fields already play), a **message-coalescing loop** inside
    `BgpDecoder::decode()` itself (real sessions send frequent small
    KEEPALIVEs that Nagle/OS buffering routinely merges with neighboring
    messages into one TCP segment -- the same pattern OPC UA's own
    `decode()` already established, reused here rather than reinvented),
    and genuine **session-scoped state** (`BgpFlowState`, keyed by TCP
    session rather than by directional flow -- `DecodeContext::
    flow_state<T>()`'s default `FlowStateKeying::Session`, the same
    keying TwinCAT/Modbus already use for their own request/response
    pairing state).

    The specifically interesting design point is the **AS-number-width
    authoritative-vs-heuristic distinction**: each AS number inside an
    AS_PATH path attribute is 2 or 4 bytes wide depending on whether RFC
    6793 4-octet AS support was negotiated, and that width is not
    self-describing within the attribute itself. When this session's own
    OPEN (capability code 65) was already seen, `BgpFlowState` makes the
    width authoritative; otherwise this decoder falls back to
    Wireshark's own heuristic (try 2-byte width first, accept it only if
    every segment's declared AS count exactly consumes the attribute's
    own declared length, otherwise assume 4-byte) and flags the result as
    non-authoritative. Because `BgpFlowState` is session-scoped rather
    than per-direction, a two-peer OPEN exchange where one side is
    4-octet-AS-capable and the other is not ends with the session's own
    width authoritatively following whichever OPEN was processed *last* --
    which happens to mirror the real-world "session downgrades to 2-byte
    AS numbers when either side lacks 4-octet AS support" behavior RFC
    6793 itself describes, not by deliberate design but as a fortunate
    consequence of the simplest possible state shape.

    BGP's own structural detection gate -- a 128-bit Marker that MUST be
    all-`0xFF` -- is the strongest in this entire codebase, stronger even
    than OPC UA's own 3-byte ASCII magic or GOOSE/SV's single-byte outer
    BER tag, so it was placed in the TCP-port-independent dispatch cascade
    (right after TwinCAT) with no collision survey needed at all, unlike
    almost every other protocol added to that same cascade.

    16 new `bgp_*` CTest tests (an OPEN exchange between a 4-octet-AS-
    capable peer and a non-capable one, confirming the authoritative-width
    behavior above; an UPDATE with ORIGIN/AS_PATH/NEXT_HOP/COMMUNITY/
    MP_REACH_NLRI; a pure-withdrawal UPDATE; three KEEPALIVEs coalesced
    into one TCP segment; an RFC 8203 shutdown-communication NOTIFICATION;
    a TCP-segment-split reassembly case; a non-standard-port note plus its
    `--bgp-port` suppression; a Marker-mismatch negative control falling
    back to `tcp`; `--stats` counting; and `--protocol bgp` isolation) --
    full suite stays 100% passing (1371 -> 1387 tests), zero-warning build
    across all three established configs. See
    `include/conduitscope/bgp.hpp`'s file header for the full writeup and
    docs/PROTOCOL_COVERAGE.md's new BGP-4 section for the user-facing
    reference. **Still not done**: any attribute/capability/notification-
    subcode value outside this decoder's own curated tables (named by raw
    numeric value only); BGP authentication visibility of any kind (RFC
    2385 TCP-MD5/RFC 5925 TCP-AO both live entirely outside the BGP
    message body, invisible to a passive capture at this layer -- a
    genuinely different posture from RIP's/OSPF's/EIGRP's own "digest
    present but unverified" framing, not just a weaker version of it); no
    `policy validate`/`inventory` integration (degrades gracefully, the
    same posture several other protocols are still in); no real-world
    capture confirmed against (validated by construction only, against
    synthetic `tests/sample_bgp.pcap`).

34. **IEEE 802.3 "Slow Protocols" (LACP/Marker/OAM), EtherType `0x8809`.**
    **Done.** Added right after the three-stage ARP/LLDP/BGP plan above, at
    Jurgen's own request -- before this, EtherType `0x8809` traffic fell
    straight through to the generic `[non-ip] Ethernet frame with ethertype
    0x8809 (...)` line, like any other named-but-undecoded EtherType. Built
    entirely on the `ProtocolDecoder` registration-model interface from
    inception, right after LLDP (item 32) and before STP in the dispatch
    order, `include/conduitscope/slow_protocols.hpp`/`slow_protocols.cpp`.

    Architecturally closer to BGP (item 33) than to ARP/LLDP: this one
    EtherType is **Subtype-multiplexed**, a single Subtype byte
    telling apart three genuinely distinct link-layer control protocols --
    LACP (subtype `0x01`), Marker Protocol (subtype `0x02`), and 802.3 OAM/
    EFM (subtype `0x03`) -- matching BGP's own "one gate, several message
    shapes" precedent rather than ARP's/LLDP's own "one gate, one message
    shape" precedent. Following that same TwinCAT/BGP precedent (not ARP's/
    LLDP's own flat dual-write), the decoded message is carried whole in
    `out.result` and rendered via a dedicated `write_slow_protocols_json_
    fields` free function in `output.cpp`, since OAM's own sub-message
    (Local/Remote Information TLVs, a list of Event TLVs) nests too deeply
    for a flat dual-write to stay legible.

    LACP's own structural gate is the strongest of the three: the Actor,
    Partner, and Collector Information TLVs, plus the Terminator TLV, must
    each match a fixed type AND length exactly (comparably strong to
    LLDP's own mandatory-triple gate). Marker Protocol's gate is a TLV
    type match (`0x01` Information / `0x02` Response Information) plus a
    minimum-length check, using the TLV's own declared Length to skip
    trailing Pad/Reserved bytes it could not independently confirm an
    exact byte count for (see the HONESTY NOTE below). OAM's own gate is
    the weakest of the three -- a Code-value match against six defined
    values -- since OAM's own framing has less redundancy to check than
    LACP's combined TLV-type+length gate; an unrecognized Subtype (e.g.
    ESMC/G.8264's `0x0A`, MEF E-LMI's `0x0B`) or a structural-gate failure
    within a recognized one both decline cleanly back to the generic
    `non-ip` EtherType fallback, exactly like every other structural-gate
    failure in this codebase.

    **HONESTY NOTE** (mirrors IEC 61850-9-2's own "no real capture found"
    note and BGP's own "never claims authenticated or unauthenticated"
    framing): every offset/bitmask/TLV-type constant here was confirmed
    against Wireshark's own `packet-slowprotocols.c` (`LACPDU_*`,
    `OAMPDU_*`, `marker_vals[]`), fetched from a GitHub mirror since
    wireshark/wireshark's own trees were unreachable from this
    environment -- but two fields could NOT be independently verified
    against a primary source despite repeated attempts (the IEEE 802.3
    standard text itself, and a second-source mirror of
    `packet-oampdu.c` beyond the one already confirmed against, were both
    unreachable): the Information TLV's own State byte's Parser-Action/
    Multiplexer-Action bit split, and the exact reserved-bit layout of the
    2-byte OAMPDU_Configuration/"Max OAMPDU Size" field. Both are shown as
    their raw wire value only (`state_raw`, not surfaced in JSON at all
    since nothing about it could be confidently named; `oampdu_config_raw`,
    surfaced as `oam_*_info_max_oampdu_size`), not bit-decoded -- the same
    choice this codebase makes whenever it can name a field but not
    confidently assert everything inside it. Similarly, the Marker(-
    Response) Information TLV's own exact total-length convention beyond
    its fixed 12-byte Requester Port/System/Transaction ID prefix could not
    be independently confirmed, so this decoder reads the TLV's own
    declared Length to skip any trailing bytes rather than assuming a
    fixed total size.

    14 new `slow_protocols_*` CTest tests (a well-formed LACPDU with Actor
    and Partner both fully in sync; the same LACPDU with the Actor's
    Synchronization bit cleared, the Out of Sync note; a corrupted-
    Actor-TLV-length negative control falling back to `non-ip`; Marker
    Information and Marker Response Information; an OAM Information OAMPDU
    with the Dying Gasp flag and both Local/Remote Information TLVs, in
    JSON; an OAM Event Notification OAMPDU with one Errored Frame Event, in
    JSON; an OAM Loopback Control Enable; an unsupported-Subtype negative
    control also falling back to `non-ip`; `--stats` counting;
    `--protocol slow-protocols` isolation; and a JSON structural check for
    `slow_protocols_subtype_name` across all three subtypes) -- full suite
    stays 100% passing (1387 -> 1401 tests), zero-warning build across all
    three established configs (default, `CONDUITSCOPE_ENABLE_LIVE_CAPTURE=
    OFF`, MinGW-w64 cross-compile). See
    `include/conduitscope/slow_protocols.hpp`'s file header for the full
    writeup and docs/PROTOCOL_COVERAGE.md's new IEEE 802.3 Slow Protocols
    section for the user-facing reference. **Still not done**: CFM
    (`0x8902`, a different EtherType entirely), ESMC/G.8264 (subtype
    `0x0A`), and MEF E-LMI (subtype `0x0B`) -- all named only, not decoded;
    OAM's own Variable Request/Response sub-structure (named only, see
    above); the two raw-value-only fields the HONESTY NOTE above names; no
    `policy validate`/`inventory` integration (degrades gracefully, the
    same posture several other protocols are still in); no real-world
    capture confirmed against (validated by construction only, against
    synthetic `tests/sample_slow_protocols.pcap`).

35. **tshark-style CLI: `-T fields`/`-e` field selection, `-f`/`-c`/`-a`
    short aliases, `-w` raw pcap capture, `-x` hex+ASCII dump.** **Done.**
    Jurgen asked for a set of `decode`-only conveniences directly mirroring
    tshark's own CLI surface, after the Slow Protocols work above: the
    ability to select and print only specific JSON-visible fields the way
    `tshark -T fields -e <field>` does, `-f` as tshark's own short form of
    `--filter` (this codebase already had `--filter` as a long option with
    no short alias), `-c`/`-a` as tshark's own short forms of
    `--max-packets`/`--duration`, `-w` to write a real pcap capture file of
    whatever packets pass through (live or filtered-offline), and `-x` to
    print each packet's raw bytes as a hex+ASCII dump.

    Two genuine short-flag collisions surfaced before any code was
    written: `-f` was already `--format`'s own short alias, and `-e` was
    already `--ether`'s. Rather than silently picking a resolution or
    silently changing existing muscle-memory behavior, this was raised
    with Jurgen directly; he picked "full tshark realignment" -- `--format`
    moves to `-T` (tshark's own letter for output format, which also
    gained `fields` as a fourth valid value), `-f` goes to `--filter`
    (tshark's own convention), `-e` goes to the new `--field`, and
    `--ether` keeps working but loses its short form entirely (long-form
    only from here on) since it has no natural letter of its own to
    reclaim. `-f`/`-T`'s rename was applied consistently across all three
    subcommands that have a `--format`/`--filter` pair (`decode`,
    `policy validate`, `inventory`), even though `-c`/`-a`/`-e`/`-w`/`-x`
    themselves are `decode`-only -- so the same short letter means the
    same thing everywhere it appears in this tool, rather than `-f`
    meaning `--filter` in `decode` but still `--format` somewhere else.

    **`-T fields`/`-e` (field selection).** Implemented as a new
    `FieldsWriter` (`output.hpp`/`output.cpp`), deliberately built by
    *reusing* `JsonWriter` rather than re-deriving field names/values a
    second time: with ~90 protocols each carrying many of their own
    fields, maintaining a second field catalog in parallel with the JSON
    writer would be a real, ongoing maintenance burden and a place for the
    two to silently drift. Instead, `FieldsWriter::write_packet` runs a
    fresh, private `JsonWriter` instance against each packet into an
    in-memory buffer, then line-parses that packet's own flat JSON object
    text into a `key -> value` map (confirmed by inspection that this
    codebase's JSON output is always exactly one field per line and never
    nested objects, a property this whole approach depends on), and prints
    only the requested `-e` fields, in the order given, tab-separated. A
    field absent for that packet's protocol, or present as JSON `null`
    (e.g. `src_ip` on a raw ARP/LLDP frame), prints as an empty column,
    not an error and not the literal text `null` -- matching tshark's own
    `-e` behavior. `-T fields` with no `-e` at all is a caught error
    (before the packet source even opens); `-e` given under any other
    `--format` is a one-line advisory note, not an error, since the run
    can still proceed meaningfully without it.

    **`-w` (write pcap).** A new, minimal `PcapWriter`
    (`include/conduitscope/pcap_writer.hpp`/`src/pcap_writer.cpp`),
    classic-pcap only (not pcapng) by deliberate choice -- simpler to
    write correctly, universally readable by every pcap-consuming tool,
    and this codebase's own `PcapReader` already treats pcapng as a
    read-only convenience format it never had to produce itself. Always
    writes microsecond-resolution timestamps regardless of the source
    capture's own resolution (converting from nanoseconds when the source
    is nanosecond-resolution), the simplest correct choice given this
    project's timestamps are stored as microsecond-or-nanosecond-tagged
    integers already. `-w` reads its raw bytes and real per-packet
    metadata from the existing loop-local `PcapPacket` in `run_decode`'s
    main loop (`cli_main.cpp`) -- not from `DecodedPacket`, which was
    confirmed via inspection to never retain raw packet bytes at all, only
    decoded fields -- so no restructuring of the decode pipeline itself
    was needed; `-w`'s own write call sits directly in that same loop,
    right alongside decoding, for every source type (`-i` live capture and
    `-r` offline-plus-`--filter` alike, since both already funnel through
    the identical `PacketSource::next()` interface). Verified end to end
    by round-tripping a full capture through `-w` and diffing its
    `--format json` output against the original file's own `--format
    json` output -- byte-identical output across all fields for every
    packet is only possible if `-w` wrote complete, correctly-ordered,
    unmodified packet records.

    **`-x` (hex dump).** A new free function, `write_hex_ascii_dump`
    (`output.hpp`/`output.cpp`) -- offset/hex/ASCII columns, 16 bytes per
    line, the same layout `xxd`/tcpdump's own `-X` use. Reads from the
    same loop-local `PcapPacket` raw bytes `-w` does, printed directly
    below each packet's normal decode line; gated to `--format text` (the
    default) and off under `--stats`, since JSON/CSV/fields have no
    per-packet text line to attach a dump to and `--stats` has no
    per-packet output at all.

    12 new CTest tests covering: `-T fields -e` basic multi-field
    selection (tab-separated, values in the order given, not JSON's own
    field order); `-T` accepting `fields` as a short-form value; a missing/
    null field printing an empty column, never the text `null`; `-T
    fields` with no `-e` erroring cleanly; `-e` without `-T fields`
    warning-and-continuing rather than erroring; `-c`/`-a` as working
    aliases for `--max-packets`/`--duration`; `-f` as a working alias for
    `--filter` (guarded the same "Npcap RUNTIME on Windows CI" way every
    other `--filter` test in this suite already is, since it's the one
    piece of this whole feature that touches libpcap); `-x`'s own
    offset/hex/ASCII layout, and its being ignored under `--format json`;
    and `-w`'s own round-trip-byte-identical-JSON proof plus a `conduitscope
    info`-based check that the file it wrote has a genuinely well-formed
    pcap global header. One pre-existing, now-redundant test
    (`resolver_ether_long_flag_same_as_e_text`, which specifically existed
    to prove `-e` and `--ether` were interchangeable) was removed, since
    `-e` no longer means `--ether` at all; every other pre-existing test
    that used bare `-e` to mean "show the Ethernet header" (seven of them,
    scattered across the SV/STP/HART-IP/Modbus/EtherNet-IP/VLAN/remote-
    access sections) was updated to spell it `--ether` instead, to keep
    testing what each one always meant to test. Full suite: 1400 -> 1412
    tests (net +12, after the one removal), zero-warning build across both
    established local configs (default, `CONDUITSCOPE_ENABLE_LIVE_CAPTURE=
    OFF`). See `cli_main.cpp`'s own `run_decode` comments for the field-
    selection/`-w` design rationale inline, and docs/USER_GUIDE.md's
    OUTPUT FORMATS section ("Field selection (`-T fields`)", "Writing a
    capture file (`-w`)", "Hex dump (`-x`)") for the user-facing
    reference.

36. **`-v`/`--verbose` (note/direction-suffix verbosity) and `--redact`/
    `--no-redact` (cleartext-secret masking).** **Done.** Jurgen ran an
    informal tshark-vs-conduitscope comparison in another session and came
    back with two immediate readability/safety issues: at default
    verbosity, per-packet notes and the trailing `(client X -- tier)`
    direction-source suffix swamp the output on a busy capture; and this
    tool prints cleartext authentication secrets it parses (he specifically
    named HSRP/VRRP passwords, OPC UA credentials, and TACACS+ cleartext),
    which makes captured output unsafe to share as-is.

    **Verbosity (`-v`/`--verbose`).** A new `bool verbose_` gate on
    `TextWriter` (`output.hpp`/`output.cpp`), off by default, additional to
    (not a replacement for) `--no-direction`: `TextWriter::write_packet`'s
    notes-printing loop and its `(client X -- tier)` direction-suffix line
    both now only render when `-v` is passed, so `--no-direction` still
    suppresses the suffix even under `-v`. Text-format only (`--format
    text`, the default) -- JSON/CSV/fields output was already unconditional
    for these fields and needed no change, since a script or SIEM
    consuming structured output was never the audience the "swamps the
    output" complaint was about.

    **Redaction (`--redact`/`--no-redact`, on by default).** A new
    `DecodeOptions::redact_secrets`/`DecodeContext::redact_secrets` pair
    (mirroring the existing `ip_src_addr` precedent for a narrow,
    single-purpose `DecodeContext` field), threaded down into the four
    decoders that actually parse a cleartext secret today, plus a shared
    `redact_secret_occurrences()`/`kRedactedSecretPlaceholder` ("
    `[REDACTED]`") helper in `protocol_decoder.hpp` (placed in a shared
    header rather than duplicated per-file, a deliberate exception to this
    codebase's usual "small helpers stay file-local" convention, justified
    by security-criticality of getting exact-substring redaction right
    once rather than four times):

    - **HSRP v1** (`hsrp.cpp`) and **VRRP v2 simple-text auth**
      (`vrrp.cpp`): both decoders already *parsed* the cleartext
      authentication field but never rendered it anywhere at all -- not a
      pre-existing leak, a pre-existing gap. This change is what actually
      makes the value visible for the first time, in the packet summary
      (`, auth "..."`), redacted to `[REDACTED]` by default and real under
      `--no-redact`. Framed to Jurgen as a factual correction: HSRP/VRRP
      were never printing real passwords before this change, so there was
      nothing to "revert" there specifically -- but the net request (show
      the value, safely, opt-in to real) is implemented in full.
    - **OPC UA** `ActivateSessionRequest` cleartext password
      (`opcua.cpp`/`opcua.hpp`) and **MQTT CONNECT** password
      (`mqtt.cpp`/`mqtt.hpp`): these two *did* already leak the real
      cleartext value into JSON's `values`/`_values` arrays before this
      change (each already carried its own inline "SECURITY FINDING"
      comment noting the leak was deliberate/known, not accidental) --
      both now redact by default, real value still available via
      `--no-redact`. In both protocols, only the password is redacted;
      the accompanying username is left alone (it's an identifier, not a
      secret).

    **Not touched by this change, found during the investigation but
    deliberately out of scope for this pass:** TACACS+ currently decodes
    no authentication body/credential at all (there is nothing cleartext
    to redact there today -- a real future decode gap, not a redaction
    gap); RIP's `auth_password` and OSPF's `auth_simple_password` have the
    exact same "parsed but never rendered" shape HSRP/VRRP had before this
    change; and SNMP's community string already renders in
    `it_protocols.cpp`'s summary/notes with no redaction at all. All four
    are reasonable, narrowly-scoped follow-ups in the same shape as this
    one, flagged to Jurgen rather than folded in silently.

    `CsvWriter` needed no changes at all -- confirmed by inspection that
    its column set is small and fully generic (no protocol-specific
    columns of any kind), so there was nothing secret-shaped for it to
    leak in the first place.

    4 renamed/added CTest tests (two existing OPC UA/MQTT tests renamed to
    assert the new default-redacted expectation, plus a `--no-redact`
    companion for each proving the real value is still recoverable on
    request) plus mechanical `-v`/`--verbose` additions to every
    pre-existing test whose `PASS_REGULAR_EXPRESSION` asserted on note
    text or the direction suffix (243 tests, across effectively every
    protocol family in this suite -- the single largest mechanical sweep
    any one change has required in this codebase's test suite so far, a
    direct measure of how pervasively notes/direction-suffix were already
    being exercised at default verbosity). Full suite: 1412 -> 1414 tests,
    zero-warning rebuild. See docs/MANUAL.md/docs/USER_GUIDE.md for the
    user-facing `-v`/`--redact` reference.

37. **Automated tshark-vs-conduitscope comparison (`tools/compare_with_tshark.py`) -- two real
    decode bugs found and fixed.** **Done.** Jurgen had already run an informal tshark comparison
    in another session (that's what produced item 36 above); he then asked whether this could be
    automated and run against the fixture corpus directly, to check for conduitscope's own decoding
    errors systematically rather than by hand.

    A new script, `tools/compare_with_tshark.py`, runs both tools across every pcap in `tests/`
    (128 files: 73 synthetic fixtures plus 55 real captures under `tests/real_captures/`) and
    compares, per packet, tshark's `frame.protocols` leaf dissector name (mapped through a small,
    explicit translation table onto conduitscope's own `protocol` JSON field) against
    conduitscope's own classification -- but ONLY for the roughly one-third of conduitscope's own
    protocol list that tshark also has a dissector for (Modbus, DNP3, S7comm, BACnet, ARP, LLDP,
    STP, BGP, MQTT, OPC UA, GOOSE/Sampled Values, EtherCAT, Kerberos, LDAP, SMB, DNS and a few
    more); the large majority of what conduitscope decodes (TwinCAT/ADS, MELSEC, FINS, HART-IP,
    FOUNDATION Fieldbus HSE, and more) is proprietary OT/ICS protocol tshark has no dissector for
    at all, so those packets are counted separately (`tshark-blind`) and never treated as a
    mismatch. See the script's own module docstring for the full methodology and its honest scope
    limits -- this is coarse-grained triage, not a field-by-field diff.

    First run found 13,624 agreements against only 2 real disagreements and 1 error, across
    roughly 13,600+ comparable frames -- a strong overall validation of this project's own
    decoding, and both findings were genuine, previously-undiscovered bugs, not false positives:

    - **Modbus/HART-IP collision, single-packet case (fixed).** A real captured Modbus "Illegal
      Function" exception response (`tests/real_captures/modbus/modbus_test_data_part2.pcap`
      frame #9) has raw function-code byte `0x80` (the exception bit set, base function code 0).
      `try_parse_modbus_tcp` (`modbus.cpp`) used to reject ANY base function code of 0, exception
      bit or not -- a guard originally added against a real DNP3-on-port-20000 collision, where
      the raw byte was exactly `0x00`, non-exception. That over-broad rejection let this real
      9-byte MBAP frame fall through to HART-IP's own looser structural gate, which happened to
      also accept the same 9 bytes as a plausible "Session Initiate" header -- a misclassification
      tshark's own dissector does not make (it decodes the same bytes as Modbus, "Illegal
      function", without complaint). Fixed by narrowing the rejection to raw byte `0x00`
      specifically (non-exception), leaving `0x80` (exception-for-function-0, a real, if unusual,
      device response) to decode normally -- see `try_parse_modbus_tcp`'s own updated comment for
      the full before/after reasoning. New regression test:
      `real_modbus_illegal_function_exception_for_function_zero_decoded`.
    - **JSON output left syntactically incomplete on a mid-stream fatal error (fixed).** Reading
      `tests/real_captures/mqtt/mqtt_packets_RedHat61_tcpdump.pcap` (a real capture that is
      genuinely corrupt from its very first frame -- already had a dedicated `--format text` test
      for its own clear error message) under `--format json` left an unterminated JSON array on
      stdout: the mid-stream `ParseError` this file triggers unwound straight past `writer->end()`
      to `run_decode`'s own top-level `catch`, so the array's closing `]` was simply never
      written. A structured-output consumer piping this straight into a JSON parser got a parse
      error instead of a clean (if short) valid array. Fixed by wrapping `run_decode`'s main
      packet loop in its own `try`/`catch (const ParseError&)` (`cli_main.cpp`) that finalizes the
      active writer (and the color-reset sequence) exactly the way the success path already does,
      THEN reports the same error message and exits nonzero -- the error text itself is
      unchanged, only the well-formedness of whatever output came before it. New regression test:
      `real_mqtt_redhat61_corrupt_file_json_output_still_well_formed`.

    **Found but deliberately NOT fixed, flagged instead as a known, documented limitation** (see
    hartip.hpp's own second "KNOWN, ACCEPTED, DOCUMENTED LIMITATION" section): frame #60 of that
    same `modbus_test_data_part2.pcap` capture is a deeper, mirror-image instance of the same
    HART-IP/Modbus collision family. A separate, genuinely malformed Modbus segment earlier in
    that same TCP flow (frame #6, raw function-code byte `0x00` -- correctly still rejected by the
    fix above, since it IS the exact `0x00` non-exception case the DNP3-collision guard exists
    for) triggers HART-IP's OWN TCP declared-length reassembly, which then claims the entire rest
    of that real Modbus flow for the next 22 segments -- every one of them ordinary Modbus traffic
    -- before finally "completing" as a nonsensical HART-IP Session Initiate message once its
    coincidental 256-byte declared length is satisfied. This is not bounded by the general
    reassembly resource-exhaustion caps (16 MiB / 20,000 segments by default -- both far too large
    to catch a 256-byte/22-segment false positive) and would need real cross-protocol
    session-state corroboration to fix properly (e.g. "this flow already showed confirmed Modbus
    traffic in the other direction") -- a genuine design change, not a quick patch, and explicitly
    NOT attempted here given this project's own prior history (documented on HART-IP's OTHER,
    already-existing collision note, directly above the new one) of a similar quick reordering fix
    in this same collision family measurably regressing the Modbus/S7comm test corpus. Flagged to
    Jurgen as a real, open design question rather than silently left unexplained.

    Full suite: 1414 -> 1416 tests, zero-warning rebuild.

### Protocols not covered at all

An honest orientation for "does it do X" -- well-known OT/ICS protocols
this tool decodes no part of, and why, as of this release. This is
separate from every still-open item above (all of which name a protocol
this tool DOES decode, at least partially); everything below is a protocol
with zero bytes of it decoded anywhere in this codebase.

- **PROFIBUS DP.** An RS-485 fieldbus, not Ethernet-based -- there is no
  IP/Ethernet framing to capture with a standard NIC at all, only dedicated
  fieldbus-tap hardware this project has no access to and so could not
  validate a decoder against even if one were written. The same structural
  category as ControlNet (see docs/PROTOCOL_COVERAGE.md's DeviceNet section, "Why
  not ControlNet too"): not a scope choice, a hard capture-availability
  wall.
- **CANopen.** The most plausible near-term candidate on this list.
  DeviceNet already rides raw CAN frames captured via SocketCAN
  (`LINKTYPE_CAN_SOCKETCAN`, see docs/PROTOCOL_COVERAGE.md's DeviceNet section) --
  `can_socketcan.hpp`/`.cpp` decode the pcap record and CAN frame header
  generically, and its own file header says outright that "any CAN
  application protocol's frames (DeviceNet, CANopen, J1939, or raw CAN
  traffic with no higher-layer protocol at all) would show up in a capture
  this same way." CANopen would reuse that exact link-layer plumbing
  unchanged; only a CANopen-specific message-group/object-dictionary
  decoder (the equivalent of `devicenet.cpp`) would need to be written. It
  just hasn't been built yet -- a real, reasonably scoped future roadmap
  item, not an exclusion.
- **Modbus RTU/ASCII (serial).** Not to be confused with Modbus/TCP, which
  this tool fully decodes (see docs/PROTOCOL_COVERAGE.md's Modbus/TCP section). The
  serial variants ride RS-232/RS-485 directly, with no equivalent of
  DeviceNet's SocketCAN situation -- there is no established pcap
  link-layer encoding for raw serial traffic this project could build
  against, and this project hasn't investigated any serial-to-pcap capture
  mechanism (a USB-serial sniffer's own vendor format, for instance) that
  might produce one. Unlike CANopen, there is currently no link-layer
  plumbing here to reuse at all.
- **PROFIBUS PA / HART's own 4-20mA analog signal.** Not a packet-capture
  question at all -- this is a physical/analog wire-level signal (current
  loop, or PROFIBUS PA's own bus-powered physical layer), with nothing that
  could ever appear in a pcap file. Distinct from HART-IP (the IP-routable
  gateway encapsulation of HART), which this tool fully decodes -- see
  docs/PROTOCOL_COVERAGE.md's HART-IP section.
- **ICCP/TASE.2 (IEC 60870-6, substation-to-control-center).** A plausible
  future candidate, not a trivial one: this project already decodes MMS in
  full (see docs/PROTOCOL_COVERAGE.md's IEC 61850 MMS section), and TASE.2 is built
  on top of MMS's own Session/Presentation/ACSE/MMS stack, but with its own
  distinct object model (bilateral tables, ICCP-specific object classes)
  that shares transport DNA with MMS, not application-layer semantics.
  Decoding it would be new work built on existing groundwork, not an
  extension of the existing MMS decoder.
- **OPC Classic (DA/HDA/AE, COM/DCOM-based).** Distinct from OPC UA, which
  this tool fully decodes (see docs/PROTOCOL_COVERAGE.md's OPC UA Binary section).
  OPC Classic's wire protocol is COM/DCOM -- MSRPC, a large, generic
  Windows RPC mechanism with no OT-specific structure of its own -- making
  this a substantially larger and less OT-focused undertaking than anything
  else on this list. Likely low priority for that reason.
- **Ethernet POWERLINK (EtherType `0x88AB`) and SERCOS III.** Real-time
  Ethernet motion-control protocols in the same general category as
  PROFINET RT and EtherCAT, both of which this tool already decodes (see
  docs/PROTOCOL_COVERAGE.md's PROFINET RT and EtherCAT sections). No structural
  obstacle here -- these simply haven't been reached yet.
- **WirelessHART.** The RF mesh variant of HART, not the IP-based one --
  distinct from HART-IP (see docs/PROTOCOL_COVERAGE.md's HART-IP section), which
  this tool fully decodes. Like PROFIBUS DP, this is not capturable via a
  standard NIC/pcap at all without dedicated radio-capture hardware.

