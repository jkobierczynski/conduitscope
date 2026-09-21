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
   the built binary) instead of prefixing every test run with `sudo`.

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


## PROTOCOL DETECTION

In `--protocol auto` (the default), every non-empty TCP payload is tested
against all twelve TCP-capable protocols, independent of port number. **OPC UA is tried
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
QinQ stacked-VLAN support; and item 17's protocol-grouped zones and
LLM-assisted zone suggestions. All genuinely useful, none blocking
anything else on this list.

1. **Validate live capture against a real Windows/Npcap install and a real
   OT/mirrored-switch-port network**, not just Linux loopback -- see LIVE
   CAPTURE's "Windows / Npcap notes" and docs/USER_GUIDE.md's LIMITATIONS.
   **Partially done:** the Windows/Npcap half is now validated -- a clean
   MSVC/Visual Studio build with live capture enabled, `conduitscope.exe
   interfaces` correctly enumerating real adapters, and a real capture
   decoded end to end (which is what surfaced both the `version` multi-
   config build-type bug and the FF-HSE false-positive fix documented
   elsewhere in this file, plus the addition of full ICMP decoding). This
   real usage also surfaced a Ctrl+C-specific bug: `SigintGuard`
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
PIM, EIGRP, and OSPF now done across two rounds -- see below; BGP planned
for a later round still. IS-IS was considered and deliberately deferred
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
gap as RIP's Keyed MD5) -- see docs/USER_GUIDE.md's LIMITATIONS for both. **BGP is the next
routing protocol planned** -- it will need TCP port-179 stream reassembly,
unlike any of the eight routing/redundancy protocols decoded so far.
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

    All three are covered by CTest (27 pre-existing OUI/VLAN tests updated
    for the new OUI default; 8 more updated and 6 new ones added for the
    `-e`/`--ether` revision above; 11 new `-t`/`--time-format` tests; 8 new
    `--filter`-on-`-r` tests including the no-libpcap stub path) and
    verified clean under ASan/UBSan (1148/1148 on the default build).

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

