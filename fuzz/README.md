# Fuzzing

libFuzzer harnesses for the parsers with the most hand-rolled length/state-machine
logic in this codebase -- see docs/DEVELOPMENT.md's "External code review and
engineering priorities" section for why these five specifically (pcap_reader, TCP
reassembly, DNP3, COTP/S7comm, MQTT) were picked first. Each harness is a thin
`LLVMFuzzerTestOneInput` wrapper around a small piece of real production code from
`conduitscope_core` -- no parsing logic is duplicated here.

## Building

Requires Clang (libFuzzer is a Clang/compiler-rt feature; GCC cannot build these
targets -- `CONDUITSCOPE_ENABLE_FUZZING` fails the CMake configure step under any
other compiler). On Debian/Ubuntu, the fuzzer and sanitizer runtimes are a separate
package from the compiler itself:

```sh
sudo apt-get install clang libclang-rt-<version>-dev   # e.g. libclang-rt-18-dev
```

```sh
cmake -S . -B build-fuzz \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCONDUITSCOPE_ENABLE_FUZZING=ON
cmake --build build-fuzz -j"$(nproc)"
```

This builds five executables in `build-fuzz/fuzz/`:

| Binary                       | Fuzzes                                                              | Seed corpus                  |
|-------------------------------|----------------------------------------------------------------------|-------------------------------|
| `fuzz_pcap_reader`            | `PcapReader` -- classic pcap AND pcapng file-format parsing          | `fuzz/corpus/pcap_reader/`    |
| `fuzz_packet_decode`          | `Decoder::decode()`, the full dispatch pipeline, over a *sequence* of packets fed to one `Decoder` instance -- this is what exercises `Decoder::reassemble_tcp_payload` (TCP segment reassembly) and every other cross-packet, per-flow state (DNP3 fragment reassembly, COTP/S7comm chaining, MQTT session-version tracking, Modbus transaction pairing) | `fuzz/corpus/packet_decode/`  |
| `fuzz_dnp3`                    | `try_parse_dnp3_link_layer` + `try_parse_dnp3_transport_and_application` (single-TCP-payload DNP3 link/transport/application parsing) | `fuzz/corpus/dnp3/`           |
| `fuzz_cotp_s7comm`             | `try_parse_tpkt_cotp` + `try_parse_s7comm` (TPKT/COTP framing, then S7comm on its user data) | `fuzz/corpus/cotp_s7comm/`    |
| `fuzz_mqtt`                     | `try_parse_mqtt_message` (MQTT v3.1/v3.1.1/v5, including Sparkplug B) | `fuzz/corpus/mqtt/`           |

## Running

Each binary is a standalone libFuzzer executable -- point it at its own corpus
directory and let it run:

```sh
./build-fuzz/fuzz/fuzz_dnp3 fuzz/corpus/dnp3/ -max_total_time=300
```

Useful flags: `-max_total_time=N` (seconds), `-jobs=N -workers=N` (parallel fuzzing,
merges crashes/coverage back into the corpus directory), `-max_len=N` (cap input
size -- these protocols are all small-frame, so 4096 or less is plenty and fuzzes
faster). A crash writes a `crash-<hash>` file in the current directory; reproduce it
directly with `./fuzz_dnp3 crash-<hash>`, and add it to the target's `fuzz/corpus/`
directory once fixed so it's replayed on every future run.

`CTest` (only when `CONDUITSCOPE_ENABLE_FUZZING=ON`) registers a short bounded run
of each target over its own seed corpus as a regression check -- `ctest -R ^fuzz_`
-- so a corpus file that used to crash and was fixed stays fixed. This is
deliberately not part of the default CTest suite or `ci.yml` yet (`CMAKE_BUILD_TYPE`
must also be a sanitizer-friendly build, and the fuzzer/sanitizer runtime package
above isn't installed on the CI image) -- folding ASan/UBSan into the CI matrix and
wiring these targets into a scheduled CI fuzzing job is the next step per
docs/DEVELOPMENT.md's adopted priority order, not yet done here.

## Corpus

`fuzz/corpus/*/` seed files are the TCP payload bytes (or, for `pcap_reader`/
`packet_decode`, whole/framed packet bytes) extracted from this repo's own existing
`tests/sample_*.pcap` fixtures -- real, known-good traffic for each protocol, so the
fuzzer starts mutating from valid structure instead of an empty corpus. They are
deliberately small; growing the corpus (via `-jobs`/merge, or by adding
interesting/crashing inputs found later) is expected over time and those additions
should be committed.

`fuzz_packet_decode`'s corpus files use a custom framing (see `fuzz_packet_decode.cpp`'s
own header comment): a sequence of `[uint16_t little-endian length][that many raw
captured-Ethernet-frame bytes]` records, so one fuzzer input drives several
`Decoder::decode()` calls against the *same* `Decoder` instance and can therefore
reach state that only exists after more than one packet.
