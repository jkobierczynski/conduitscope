# DataFW1_5 fix -- file manifest

Drop this into the root of your conduitscope checkout; every path below
mirrors the project layout, so files land where they belong and overwrite
the ones this change touches.

- src/s7commplus.cpp                          -- new decode_integrity_fw1_5(), merged Data/DataFW1_5 dispatch
- include/conduitscope/s7commplus.hpp         -- updated wire-format + Tier-1 doc comments
- include/conduitscope/decoder.hpp            -- fixed stale s7plus_integrity_digest_present comment
- docs/PROTOCOL_COVERAGE.md                   -- DataFW1_5 moved from Tier-2 to Tier-1, new real-capture writeup
- docs/USER_GUIDE.md                          -- LIMITATIONS + field reference updated for DataFW1_5
- docs/DEVELOPMENT.md                         -- fuzzing campaign log table, TCP-reassembly-cap "implemented" note, roadmap item corrected
- README.md                                   -- DataFW1_5 summary corrected
- tools/make_sample_pcap.py                   -- synthetic DataFW1_5 fixture now carries a realistic leading integrity block
- tests/sample_s7commplus.pcap                -- regenerated binary fixture (from the script above)
- CMakeLists.txt                              -- new/updated CTest cases for DataFW1_5
- tests/real_captures/s7comm/ATTRIBUTION.md   -- new addendum: the real S7-1212C + KTP 400 Basic capture finding
- fuzz/corpus/s7comm_plus/*                   -- 31 new real-device seeds (sha1-named, content-addressed; already merged into this project's own copy)

Verified: full CTest suite 1107/1107 passing; a 4-worker/60s ASan+UBSan
fuzz burst (~1.8M executions) against fuzz_s7comm_plus with these seeds
plus the existing corpus found 0 crashes.
