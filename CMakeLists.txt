# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.16)
project(conduitscope VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Embeds the project version / compiler / build type into the binary so
# `conduitscope version` can report exactly what it's running, without
# depending on git being present (this groundwork checkout may or may not be
# a git repo yet).
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/conduitscope/version.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/conduitscope/version.hpp"
  @ONLY
)

add_library(conduitscope_core STATIC
  src/byteio.cpp
  src/pcap_reader.cpp
  src/link_layer.cpp
  src/ipv4.cpp
  src/tcp.cpp
  src/udp.cpp
  src/modbus.cpp
  src/dnp3.cpp
  src/iec104.cpp
  src/enip.cpp
  src/profinet.cpp
  src/goose.cpp
  src/sv.cpp
  src/ethercat.cpp
  src/bacnet.cpp
  src/cotp.cpp
  src/s7comm.cpp
  src/decoder.cpp
  src/output.cpp
  src/yaml_mini.cpp
  src/policy.cpp
  src/policy_engine.cpp
  src/live_capture.cpp
)
target_include_directories(conduitscope_core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

if(MSVC)
  target_compile_options(conduitscope_core PRIVATE /W4 /permissive-)
else()
  target_compile_options(conduitscope_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# --------------------------------------------------------------------------------------------
# Optional live-capture support (libpcap on Linux, the Npcap SDK on Windows). This is the ONE
# exception to the project's otherwise zero-external-dependency design (see README.md's "Why
# offline pcap files" section) -- and it stays optional even where it's found: when neither is
# present, conduitscope_core still builds exactly as it always has, and live_capture.cpp's stub
# implementation (see its own comment) makes `-i/--interface` and `conduitscope interfaces` fail
# with a clear message instead of not existing at all.
#
# CONDUITSCOPE_ENABLE_LIVE_CAPTURE lets a builder opt out of even searching (e.g. a packager who
# wants a guaranteed-dependency-free build regardless of what happens to be installed on the build
# machine); it defaults on since the search itself is harmless when nothing is found.
# --------------------------------------------------------------------------------------------
option(CONDUITSCOPE_ENABLE_LIVE_CAPTURE
  "Search for libpcap (Linux) / the Npcap SDK (Windows) and build live-capture support if found"
  ON)

set(CONDUITSCOPE_HAVE_PCAP FALSE)
if(CONDUITSCOPE_ENABLE_LIVE_CAPTURE)
  if(WIN32)
    # The Npcap SDK (distinct from the Npcap runtime installer -- see docs/MANUAL.md's LIVE
    # CAPTURE section) ships pcap.h under Include/ and import libraries under Lib/ (32-bit) or
    # Lib/x64/ (64-bit); it has no standard install location, so NPCAP_SDK_DIR (an environment or
    # CMake variable) is how a builder points at it, alongside the common default install path.
    set(_conduitscope_npcap_sdk_dir "$ENV{NPCAP_SDK_DIR}")
    if(NOT _conduitscope_npcap_sdk_dir AND DEFINED NPCAP_SDK_DIR)
      set(_conduitscope_npcap_sdk_dir "${NPCAP_SDK_DIR}")
    endif()
    find_path(PCAP_INCLUDE_DIR pcap.h
      HINTS "${_conduitscope_npcap_sdk_dir}/Include" "C:/Npcap-SDK/Include")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(_conduitscope_npcap_lib_subdir "Lib/x64")
    else()
      set(_conduitscope_npcap_lib_subdir "Lib")
    endif()
    find_library(PCAP_LIBRARY NAMES wpcap
      HINTS "${_conduitscope_npcap_sdk_dir}/${_conduitscope_npcap_lib_subdir}"
            "C:/Npcap-SDK/${_conduitscope_npcap_lib_subdir}")
    unset(_conduitscope_npcap_sdk_dir)
    unset(_conduitscope_npcap_lib_subdir)
  else()
    find_path(PCAP_INCLUDE_DIR pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)
  endif()

  if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    set(CONDUITSCOPE_HAVE_PCAP TRUE)
    target_compile_definitions(conduitscope_core PUBLIC CONDUITSCOPE_HAVE_PCAP=1)
    target_include_directories(conduitscope_core PRIVATE "${PCAP_INCLUDE_DIR}")
    target_link_libraries(conduitscope_core PUBLIC "${PCAP_LIBRARY}")
    message(STATUS "conduitscope: live capture ENABLED (found ${PCAP_LIBRARY})")
  else()
    message(STATUS "conduitscope: live capture DISABLED (libpcap/Npcap SDK not found -- "
                    "'-i/--interface' and 'interfaces' will report this clearly at runtime; "
                    "everything else is unaffected)")
  endif()
else()
  message(STATUS "conduitscope: live capture DISABLED (CONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF)")
endif()

# CLI11 is vendored as a single header under third_party/ specifically so this
# project has ZERO external dependencies to install on either platform -- no
# vcpkg/conan/apt package needed, just a C++17 compiler and CMake.
add_executable(conduitscope src/cli_main.cpp)
target_link_libraries(conduitscope PRIVATE conduitscope_core)
target_include_directories(conduitscope PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/third_party/CLI11")

if(MSVC)
  target_compile_options(conduitscope PRIVATE /W4 /permissive-)
else()
  target_compile_options(conduitscope PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS conduitscope RUNTIME DESTINATION bin)
if(UNIX)
  install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/conduitscope.1" DESTINATION share/man/man1)
endif()

enable_testing()

add_test(NAME decode_modbus_sample
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --format json)
set_tests_properties(decode_modbus_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "Read Holding Registers")

add_test(NAME decode_dnp3_sample
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(decode_dnp3_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "DNP3 data link frame")

add_test(NAME dnp3_no_user_data_stays_link_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_no_user_data_stays_link_only PROPERTIES
  PASS_REGULAR_EXPRESSION "user_data=0 byte\\(s\\)"
  FAIL_REGULAR_EXPRESSION "user_data=0 byte\\(s\\)\\; transport")

add_test(NAME dnp3_transport_and_read_class0_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_transport_and_read_class0_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "transport: FIR=1 FIN=1 SEQ=0 \\| application:.*function=Read \\(0x01\\) objects: \\[g60v1\\]")

# The response packet's logical payload is 23 bytes -- over the 16-byte data-link block size --
# so this is also the regression guard for the multi-block CRC reassembly logic: if it mis-skips
# a block CRC, the object headers below would decode to garbage or fail to decode at all.
add_test(NAME dnp3_response_multiblock_object_headers
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_response_multiblock_object_headers PROPERTIES
  PASS_REGULAR_EXPRESSION "object 0: g1v2 \\(Binary Input\\) qualifier=0x00 range=0-2 -- 3 point\\(s\\), 3 byte\\(s\\) of object data")

add_test(NAME dnp3_response_second_object_after_block_boundary
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_response_second_object_after_block_boundary PROPERTIES
  PASS_REGULAR_EXPRESSION "object 1: g30v1 \\(Analog Input\\) qualifier=0x00 range=0-0 -- 1 point\\(s\\), 5 byte\\(s\\) of object data")

add_test(NAME dnp3_response_iin_flags_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_response_iin_flags_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Response \\(0x81\\) IIN=0x0080 \\[DEVICE_RESTART\\]")

# Multi-data-link-frame fragment (transport FIN=0): application layer must be left undecoded,
# not guessed at from the arbitrary trailing bytes in this fixture.
add_test(NAME dnp3_multiframe_fragment_application_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_multiframe_fragment_application_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "transport: FIR=1 FIN=0 SEQ=0"
  FAIL_REGULAR_EXPRESSION "transport: FIR=1 FIN=0 SEQ=0 \\| application")

add_test(NAME dnp3_unsupported_prefix_code_falls_back
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_unsupported_prefix_code_falls_back PROPERTIES
  PASS_REGULAR_EXPRESSION "prefix code 0x04 \\(object-size-prefixed or reserved\\), which this groundwork release does not decode")

add_test(NAME dnp3_function_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_function_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_function\": \"Response\"")

add_test(NAME dnp3_objects_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_objects_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_objects\": \\[\"g1v2 \\(Binary Input\\)\", \"g30v1 \\(Analog Input\\)\"\\]")

# Point-value decoding: byte 0 of the g1v2 object data is 0x81 (ONLINE flag + STATE bit set) --
# must decode to value "1" with the ONLINE flag, not just the raw byte length.
add_test(NAME dnp3_binary_input_value_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_binary_input_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "idx=0: 1 \\[ONLINE\\]")

add_test(NAME dnp3_analog_input_value_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_analog_input_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g30v1.*idx=0: 0 \\[ONLINE\\]")

# CROB command decode: control byte 0x43 = trip/close Close(1), control code Latch On(3);
# on_time=1000ms, off_time=0ms, status=0 (Success). High security relevance -- this is literally
# how DNP3 issues output commands, so getting every field named correctly matters.
add_test(NAME dnp3_crob_value_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_crob_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "idx=7: code=Latch On tc=Close queue/clear=0x00 count=1 on_time=1000ms off_time=0ms status=Success")

add_test(NAME dnp3_values_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_values_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_values\": \\[\"g1v2 idx=0: 1 \\[ONLINE\\]\"")

# Two complete DNP3 data-link frames coalesced into one TCP payload (packet 7 of
# sample_dnp3.pcap): the first frame's own function/summary must still be the headline, and the
# second frame -- previously silently dropped, since try_parse_dnp3_link_layer only ever looked
# at the start of the payload -- must now be fully decoded and surfaced via a note, not lost.
add_test(NAME dnp3_coalesced_frames_first_summary_unaffected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_coalesced_frames_first_summary_unaffected PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Read \\(0x01\\) objects: \\[g60v1\\]")

add_test(NAME dnp3_coalesced_second_frame_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_coalesced_second_frame_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "additional DNP3 data link frame 2 found in the same TCP payload at byte offset 18")

add_test(NAME dnp3_coalesced_second_frame_objects_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_coalesced_second_frame_objects_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g12v1 \\(Binary Output Command \\(CROB\\)\\).*idx=7: code=Latch On")

add_test(NAME dnp3_coalesced_frames_merged_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_coalesced_frames_merged_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_objects\": \\[\"g60v1 \\(Class Objects\\)\", \"g12v1 \\(Binary Output Command \\(CROB\\)\\)\"\\]")

# --------------------------------------------------------------------------
# Cross-packet DNP3 fragment reassembly (packets 8-12 of sample_dnp3.pcap): a fragment split
# across multiple data-link frames arriving in SEPARATE TCP segments/pcap packets, requiring the
# per-TCP-flow state Decoder::process_dnp3_frame maintains across decode() calls -- distinct from
# the same-TCP-payload frame coalescing (Problem A) tested above.
# --------------------------------------------------------------------------

# The FIR=1,FIN=0 starting frame (packet 8) must show only its own transport header -- nothing
# decoded yet -- plus a note that reassembly has begun and is buffering.
add_test(NAME dnp3_reassembly_start_frame_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_start_frame_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "beginning a DNP3 fragment that spans multiple data-link frames \\(FIR=1, FIN=0, SEQ=5\\)"
  FAIL_REGULAR_EXPRESSION "transport: FIR=1 FIN=0 SEQ=5 \\| application")

# The FIN=1 completing frame (packet 9, a separate pcap packet from packet 8) must decode the
# full, concatenated application layer -- same CROB command as the single-frame packet 6, but
# reconstructed from two frames delivered a packet apart.
add_test(NAME dnp3_reassembly_completes_across_packets
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_completes_across_packets PROPERTIES
  PASS_REGULAR_EXPRESSION "completed a 2-data-link-frame DNP3 fragment reassembled across separate TCP segments \\(18 application-layer byte\\(s\\) total\\)")

add_test(NAME dnp3_reassembly_completed_object_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_completed_object_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Direct Operate \\(0x05\\) objects: \\[g12v1\\].*idx=7: code=Latch On tc=Close")

add_test(NAME dnp3_reassembly_completed_function_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_reassembly_completed_function_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 9,[^}]*\"dnp3_function\": \"Direct Operate\"")

# packet 5 (FIR=1,FIN=1, same TCP flow as packet 4's never-completed start) must abandon packet
# 4's stale in-progress reassembly rather than silently merging into it.
add_test(NAME dnp3_reassembly_abandoned_by_new_complete_fragment
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_abandoned_by_new_complete_fragment PROPERTIES
  PASS_REGULAR_EXPRESSION "a complete single-frame DNP3 fragment \\(FIR=1, FIN=1\\) arrived on this TCP flow while a previous multi-frame fragment reassembly was still in progress")

# packet 10: a FIR=0 continuation with no reassembly in progress on its flow at all (orphan) --
# must be left transport-only, with an explanatory note, never guessed at.
add_test(NAME dnp3_reassembly_orphan_continuation_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_orphan_continuation_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "continuation DNP3 data-link frame \\(FIR=0, SEQ=1\\) with no fragment reassembly in progress on this TCP flow")

# packets 11-12: a sequence-number mismatch must discard the in-progress reassembly rather than
# concatenating bytes out of order.
add_test(NAME dnp3_reassembly_sequence_mismatch_discarded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_sequence_mismatch_discarded PROPERTIES
  PASS_REGULAR_EXPRESSION "continuation DNP3 data-link frame's sequence number \\(35\\) does not follow the previous frame's \\(expected 11\\)")

add_test(NAME stats_mode_dnp3
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --stats)
set_tests_properties(stats_mode_dnp3 PROPERTIES
  PASS_REGULAR_EXPRESSION "dnp3 function codes:")

# --------------------------------------------------------------------------
# General TCP stream reassembly (Decoder::reassemble_tcp_payload / tcp_reassembly_) -- a single
# PDU/frame's own bytes split across TCP segments, one flow-level layer below DNP3's own
# application-fragment reassembly tested above. tests/sample_tcp_reassembly.pcap, scenarios A-F.
# --------------------------------------------------------------------------

# A) Modbus response ADU split across two TCP segments: the first segment alone must show only
# "buffering", never a modbus decode; the second must complete it correctly.
add_test(NAME tcp_reassembly_modbus_first_segment_buffers
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_modbus_first_segment_buffers PROPERTIES
  PASS_REGULAR_EXPRESSION "buffering a Modbus/TCP PDU/frame split across TCP segments 502->51600: 15 of 29 declared byte\\(s\\)")

# [^#] rather than a bare .* binds the match to one packet's own block of output (every packet's
# block starts with a line beginning "#<index>", and nothing inside a block contains '#') -- .*
# alone would span the WHOLE command output across every packet, so a later, unrelated packet's
# text (several other scenarios below decode to this same "response: 20 data byte(s) = 00 00 00
# 01..." text, being built from the same register values) could satisfy it just as well, proving
# nothing about which packet actually produced it. Same technique already used for the JSON
# per-object checks above (there bounded by '}' instead of '#').
add_test(NAME tcp_reassembly_modbus_completes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_modbus_completes PROPERTIES
  PASS_REGULAR_EXPRESSION "response: 20 data byte\\(s\\) = 00 00 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00 08 00 09[^#]*reassembled a Modbus/TCP PDU/frame from 29 byte\\(s\\) spanning 2 TCP segments")

# B) A complete single-data-link-frame DNP3 fragment split mid-*header* across two TCP segments.
add_test(NAME tcp_reassembly_dnp3_link_layer_completes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_dnp3_link_layer_completes PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Read \\(0x01\\) objects: \\[g60v1\\][^#]*reassembled a DNP3 data-link PDU/frame from 18 byte\\(s\\) spanning 2 TCP segments")

# C) A TPKT/S7comm Setup Communication request split across two TCP segments.
add_test(NAME tcp_reassembly_tpkt_s7comm_completes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_tpkt_s7comm_completes PROPERTIES
  PASS_REGULAR_EXPRESSION "Setup Communication \\(negotiated PDU length=240[^#]*reassembled a TPKT/COTP PDU/frame from 25 byte\\(s\\) spanning 2 TCP segments")

# D) A TCP sequence gap abandons the in-progress reassembly, and a later, ordinary request on the
# same flow still decodes normally afterward (the abandoned state doesn't wedge the flow).
add_test(NAME tcp_reassembly_gap_abandons_reassembly
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_gap_abandons_reassembly PROPERTIES
  PASS_REGULAR_EXPRESSION "TCP sequence gap on this flow \\(expected seq 30009, got 30509, 500 byte\\(s\\) apparently missing\\) -- abandoning an in-progress 9-byte PDU/frame reassembly")

add_test(NAME tcp_reassembly_flow_recovers_after_gap
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_flow_recovers_after_gap PROPERTIES
  PASS_REGULAR_EXPRESSION "request: read 10 holding register\\(s\\) starting at address 0")

# E) A fully-duplicate retransmission mid-reassembly is ignored, not misapplied; the real
# completing segment afterward still finishes the PDU correctly.
add_test(NAME tcp_reassembly_duplicate_retransmit_ignored
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_duplicate_retransmit_ignored PROPERTIES
  PASS_REGULAR_EXPRESSION "retransmitted/duplicate TCP segment 502->51604 \\(fully overlaps bytes already buffered for an in-progress 20-byte PDU/frame reassembly")

add_test(NAME tcp_reassembly_completes_despite_duplicate
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_completes_despite_duplicate PROPERTIES
  PASS_REGULAR_EXPRESSION "response: 20 data byte\\(s\\) = 00 00 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00 08 00 09[^#]*reassembled a Modbus/TCP PDU/frame from 29 byte\\(s\\) spanning 3 TCP segments")

# F) A partial-overlap retransmission (repeats a few already-buffered bytes, then extends past
# them with new ones) is trimmed to just its new bytes, not misaligned or duplicated.
add_test(NAME tcp_reassembly_partial_overlap_trimmed
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_partial_overlap_trimmed PROPERTIES
  PASS_REGULAR_EXPRESSION "TCP segment on this flow overlaps 3 already-buffered byte\\(s\\) \\(likely a retransmission\\) -- trimmed and only the new byte\\(s\\) appended")

add_test(NAME tcp_reassembly_partial_overlap_completes_correctly
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_partial_overlap_completes_correctly PROPERTIES
  PASS_REGULAR_EXPRESSION "response: 20 data byte\\(s\\) = 00 00 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00 08 00 09[^#]*reassembled a Modbus/TCP PDU/frame from 29 byte\\(s\\) spanning 3 TCP segments")

# --------------------------------------------------------------------------
# Real-world DNP3 captures (not synthetic, unlike tests/sample_dnp3.pcap above),
# sourced from github.com/automayt/ICS-pcap -- see
# tests/real_captures/dnp3/ATTRIBUTION.md for exact provenance, why these
# particular captures, and licensing notes.
# --------------------------------------------------------------------------
set(DNP3_REAL_CAPTURES
  dnp3_read
  dnp3_read_request
  dnp3_write
  dnp3_write_request
  dnp3_select_operate
  dnp3_select_operate_request
  dnp3_request_link
  dnp3_request_link_status
  dnp3_malformed
  dnp3_test_data_part1
  dnp3_test_data_part2
)
# Baseline regression guard for every one of them: real (including deliberately
# malformed/fuzzed) traffic must never crash the parser or make it exit non-zero,
# independent of whatever it does or doesn't manage to decode. CTest already
# fails a test on a non-zero exit code, so no PASS_REGULAR_EXPRESSION is needed
# here -- that would only test that decode ran, which the exit code already covers.
foreach(capture ${DNP3_REAL_CAPTURES})
  add_test(NAME real_dnp3_${capture}_does_not_crash
    COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/${capture}.pcap" --format json)
endforeach()

add_test(NAME real_dnp3_read_class1_poll_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_read.pcap" --format text)
set_tests_properties(real_dnp3_read_class1_poll_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Read \\(0x01\\) objects: \\[g60v2\\]")

# Real Select/Operate CROB sequence -- confirms the field-by-field CROB decode
# (control code, trip/close, queue/clear, on/off time, status) against an
# independent DNP3 master's actual wire encoding, not just the synthetic
# fixture's one hand-constructed control byte.
add_test(NAME real_dnp3_select_operate_crob_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_select_operate.pcap" --format text)
set_tests_properties(real_dnp3_select_operate_crob_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "idx=1: code=Latch On tc=NUL queue/clear=0x00 count=1 on_time=100ms off_time=100ms status=Success")

# Same CROB object, but a real operate attempt that the outstation rejected --
# confirms the IEEE 1815 control-status-code table isn't only decoding whichever
# single status value the synthetic fixture happens to use.
add_test(NAME real_dnp3_test_data_part2_crob_status_success
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part2.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part2_crob_status_success PROPERTIES
  PASS_REGULAR_EXPRESSION "status=Success")

add_test(NAME real_dnp3_test_data_part2_crob_status_not_supported
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part2.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part2_crob_status_not_supported PROPERTIES
  PASS_REGULAR_EXPRESSION "status=Not Supported")

# Real polling session: Binary Input (bit-packed), Binary Output (byte-per-point
# with flags), and Internal Indications objects all decoded from real traffic.
add_test(NAME real_dnp3_test_data_part1_binary_input_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part1.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part1_binary_input_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g1v1 \\(Binary Input\\).*idx=0: 0, idx=1: 1, idx=2: 0")

add_test(NAME real_dnp3_test_data_part1_binary_output_flags_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part1.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part1_binary_output_flags_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g10v2 \\(Binary Output\\).*idx=0: 0 \\[ONLINE\\]")

add_test(NAME real_dnp3_test_data_part1_internal_indications_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part1.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part1_internal_indications_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g80v1 \\(Internal Indications\\).*idx=7: 0")

# Absolute timestamp (group 50 var 1) from a real Write request, not the
# synthetic fixture.
add_test(NAME real_dnp3_write_timestamp_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_write.pcap" --format text)
set_tests_properties(real_dnp3_write_timestamp_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g50v1 \\(Time and Date\\).*idx=0: 1156521360890ms-since-epoch")

# Deliberately corrupted/fuzzed capture: must degrade gracefully (a note
# explaining why parsing stopped) rather than silently fabricate a value for
# bytes that don't actually decode to anything meaningful.
add_test(NAME real_dnp3_malformed_bails_out_with_a_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_malformed.pcap" --format text)
set_tests_properties(real_dnp3_malformed_bails_out_with_a_note PROPERTIES
  PASS_REGULAR_EXPRESSION "is not in the known point-format table -- stopping object parsing")

# --------------------------------------------------------------------------
# Link/IP-layer plumbing (synthetic, tests/sample_link_transport_layers.pcap): non-IPv4
# Ethernet frames and non-TCP IPv4 payloads (including UDP), named when the ethertype/IP-
# protocol-number/UDP-port is a recognized one and left as a bare number otherwise -- see
# tools/make_sample_pcap.py's build_link_and_transport_layer_sample for the exact byte layout,
# and link_layer.hpp/ipv4.hpp/decoder.cpp for the naming tables themselves.
# --------------------------------------------------------------------------
add_test(NAME link_layer_arp_ethertype_named
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_link_transport_layers.pcap" --format text)
set_tests_properties(link_layer_arp_ethertype_named PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-ip\\]  Ethernet frame with ethertype 0x806 \\(ARP\\) \\(not IPv4\\)")

add_test(NAME link_layer_raw_ethernet_ot_protocols_named
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_link_transport_layers.pcap" --format text)
set_tests_properties(link_layer_raw_ethernet_ot_protocols_named PROPERTIES
  PASS_REGULAR_EXPRESSION "ethertype 0x8892 \\(PROFINET RT\\)[^\n]*\n.*ethertype 0x88b8 \\(IEC 61850-8-1 GOOSE\\)")

add_test(NAME link_layer_unrecognized_ethertype_stays_unnamed
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_link_transport_layers.pcap" --format text)
set_tests_properties(link_layer_unrecognized_ethertype_stays_unnamed PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-ip\\]  Ethernet frame with ethertype 0x9999 \\(not IPv4\\)")

add_test(NAME ip_layer_icmp_protocol_number_named
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_link_transport_layers.pcap" --format text)
set_tests_properties(ip_layer_icmp_protocol_number_named PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-tcp\\]  IPv4 protocol number 1 \\(ICMP\\) \\(not TCP\\)")

# Arbitrary, too-short bytes on EtherNet/IP's own CIP I/O port (2222) must NOT be misdetected as
# CIP I/O -- try_parse_cip_io's structural gate (see its header comment in enip.hpp) correctly
# declines and this falls through to the generic "udp" tag, same as any other unrecognized UDP
# traffic. See tests/sample_enip_cip_io.pcap (build_enip_cip_io_sample) for genuine CIP I/O
# decoding coverage.
add_test(NAME udp_port_2222_garbage_not_misdetected_as_cip_io
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_link_transport_layers.pcap" --format text)
set_tests_properties(udp_port_2222_garbage_not_misdetected_as_cip_io PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 4 byte\\(s\\) on port 2222->55000\n")

add_test(NAME udp_unnamed_port_and_empty_payload_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_link_transport_layers.pcap" --format text)
set_tests_properties(udp_unnamed_port_and_empty_payload_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP datagram with no payload on port 51999->51998")

add_test(NAME udp_ports_populate_json_and_csv
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_link_transport_layers.pcap")
set_tests_properties(udp_ports_populate_json_and_csv PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"udp\",\n    \"summary\": \"UDP payload of 4 byte\\(s\\) on port 2222->55000")

# policy validate must not crash and must correctly count every one of these as skipped_non_tcp
# (this groundwork release's plumbing makes UDP/non-IP traffic visible in `decode`, but the
# policy engine does not yet evaluate it against any conduit -- see PolicyEngine::observe's
# doc comment and docs/MANUAL.md's ROADMAP).
add_test(NAME link_transport_layers_all_skipped_by_policy_engine
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_link_transport_layers.pcap"
          --policy "${CMAKE_CURRENT_SOURCE_DIR}/tests/policies/compliant.yaml" --format json)
set_tests_properties(link_transport_layers_all_skipped_by_policy_engine PROPERTIES
  PASS_REGULAR_EXPRESSION "\"total_packets\": 7,\n  \"skipped_non_tcp\": 7")

# --------------------------------------------------------------------------
# IEC 60870-5-104 (synthetic, tests/sample_iec104.pcap): U-format handshakes, a general
# interrogation activation/confirmation, a sequential-IOA (SQ=1) monitoring report, a
# time-tagged measured value, a double command with a negative activation confirmation, and an
# S-format supervisory ack -- see tools/make_sample_pcap.py's build_iec104_sample for the exact
# byte layout each assertion below is checking.
# --------------------------------------------------------------------------
add_test(NAME iec104_startdt_handshake_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104.pcap" --format text)
set_tests_properties(iec104_startdt_handshake_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "U-format STARTDT act[^\n]*\n.*U-format STARTDT con")

add_test(NAME iec104_testfr_keepalive_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104.pcap" --format text)
set_tests_properties(iec104_testfr_keepalive_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "U-format TESTFR act[^\n]*\n.*U-format TESTFR con")

add_test(NAME iec104_general_interrogation_activation_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104.pcap" --format text)
set_tests_properties(iec104_general_interrogation_activation_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "C_IC_NA_1 \\(Interrogation command\\) COT=activation CASDU=1 objects=1")

add_test(NAME iec104_sequential_single_point_report_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104.pcap")
set_tests_properties(iec104_sequential_single_point_report_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=100: ON\", \"ioa=101: OFF \\[IV\\]\", \"ioa=102: ON \\[BL\\]\"\\]")

add_test(NAME iec104_time_tagged_measured_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104.pcap")
set_tests_properties(iec104_time_tagged_measured_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "ioa=200: 16384 \\(0\\.5000\\) @ 2024-03-15 10:30:00\\.500")

add_test(NAME iec104_double_command_negative_confirmation_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104.pcap" --format text)
set_tests_properties(iec104_double_command_negative_confirmation_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "C_DC_NA_1 \\(Double command\\) COT=activation confirmation \\[NEG\\] CASDU=1 objects=1")

add_test(NAME iec104_s_format_supervisory_ack_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104.pcap" --format text)
set_tests_properties(iec104_s_format_supervisory_ack_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "S-format \\(supervisory\\) N\\(R\\)=4")

# Regression fixture for the IEC104-vs-Modbus detection collision found while scoping this
# feature (see try_parse_iec104_apci's header comment in iec104.hpp and the dispatch-order
# comment in decoder.cpp): an I-format APDU with N(S)=N(R)=0 whose APCI bytes also read as a
# plausible Modbus/TCP MBAP header (protocol-id==0, mbap_length==0, a non-zero "function code")
# must be classified as iec104, not modbus.
add_test(NAME iec104_wins_modbus_detection_collision
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_modbus_precedence.pcap" --format text)
set_tests_properties(iec104_wins_modbus_detection_collision PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[iec104\\]  I-format N\\(S\\)=0 N\\(R\\)=0; C_IC_NA_1")

# --------------------------------------------------------------------------
# Real-world IEC 60870-5-104 captures -- see tests/real_captures/iec104/ATTRIBUTION.md for
# provenance. Three sourced from public Wireshark/ICS-pcap test-capture collections (the
# Wireshark wiki's own iec104.pcap sample, a diverse 2010 simulated hydro-plant capture, and a
# 2008 dissector test file), plus the three station-address captures from Netresec's public
# Industroyer2 release -- real, attributed nation-state ICS malware traffic against a live
# IEC 104 RTU, not a synthetic or generic test vector.
# --------------------------------------------------------------------------
set(IEC104_REAL_CAPTURES
  iec104_wireshark_wiki
  iec104_090813_diverse
  iec104_test_dissect
  industroyer2_station1
  industroyer2_station2
  industroyer2_station3
)
# Same baseline regression guard as the DNP3/Modbus real-capture loops above: must never crash
# the parser or exit non-zero, independent of what it does or doesn't manage to decode.
foreach(capture ${IEC104_REAL_CAPTURES})
  add_test(NAME real_iec104_${capture}_does_not_crash
    COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/iec104/${capture}.pcap" --format json)
endforeach()

# The Wireshark wiki sample: a clean TESTFR/STARTDT handshake followed by a general
# interrogation that returns (among others) a real M_SP_NA_1 report -- confirms the decoder
# against an independent IEC 104 stack's actual wire encoding, not just the synthetic fixture's
# hand-constructed bytes.
add_test(NAME real_iec104_wireshark_wiki_general_interrogation_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/iec104/iec104_wireshark_wiki.pcap" --format text)
set_tests_properties(real_iec104_wireshark_wiki_general_interrogation_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "C_IC_NA_1 \\(Interrogation command\\) COT=activation CASDU=10 objects=1")

# 090813_diverse.pcap: a simulated hydro-plant floodgate-manipulation scenario (subject of
# Netresec's 2012 "SCADA Network Forensics with IEC-104" post) -- real command/setpoint traffic,
# not just monitoring, including the short-floating-point setpoint command (type 50) this
# decoder table covers.
add_test(NAME real_iec104_090813_diverse_setpoint_command_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/iec104/iec104_090813_diverse.pcap" --format text)
set_tests_properties(real_iec104_090813_diverse_setpoint_command_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "C_SE_NC_1 \\(Set point command, short floating point\\)")

# TestDissectIec104.pcap: a 2008 Wireshark dissector test file specifically exercising clock
# synchronization (type 103) and end-of-initialization (type 70) -- type IDs the other two real
# captures don't happen to carry.
add_test(NAME real_iec104_test_dissect_clock_sync_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/iec104/iec104_test_dissect.pcap" --format text)
set_tests_properties(real_iec104_test_dissect_clock_sync_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "C_CS_NA_1 \\(Clock synchronization command\\)")

# Industroyer2: real double-command (C_DC_NA_1) breaker-manipulation traffic against a live RTU,
# most of which the RTU refused (negative activation confirmation) -- documented, attributed
# nation-state ICS malware behavior, not a hypothetical.
add_test(NAME real_iec104_industroyer2_double_command_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/iec104/industroyer2_station1.pcap" --format text)
set_tests_properties(real_iec104_industroyer2_double_command_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "C_DC_NA_1 \\(Double command\\) COT=activation confirmation \\[NEG\\] CASDU=1 objects=1")

# --------------------------------------------------------------------------
# EtherNet/IP + CIP explicit messaging (synthetic, tests/sample_enip.pcap): a RegisterSession/
# UnRegisterSession handshake, a ListIdentity request/response (device-fingerprinting fields), and
# a symbolic (ANSI Extended Symbol segment 0x91) Read_Tag/Write_Tag round trip -- see
# tools/make_sample_pcap.py's build_enip_sample for the exact byte layout each assertion below is
# checking.
# --------------------------------------------------------------------------
add_test(NAME enip_register_session_handshake_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip.pcap" --format text)
set_tests_properties(enip_register_session_handshake_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[enip\\]  RegisterSession; protocol version 1, options flags 0x0000[^\n]*\n.*\\[enip\\]  RegisterSession; protocol version 1, options flags 0x0000")

add_test(NAME enip_list_identity_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip.pcap" --format text)
set_tests_properties(enip_list_identity_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "ListIdentity; identity: vendor=1 device_type=12 product_code=54 rev=2\\.1 serial=0x1337ab name=\"Conduit-ENIP-Sample\"")

add_test(NAME enip_symbolic_read_tag_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip.pcap")
set_tests_properties(enip_symbolic_read_tag_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"enip_cip_path\": \"Pump1_Speed\",\n    \"enip_cip_values\": \\[\"element_count=1\"\\]")

add_test(NAME enip_symbolic_read_tag_response_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip.pcap")
set_tests_properties(enip_symbolic_read_tag_response_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"enip_cip_values\": \\[\"type=DINT\", \"42\"\\]")

add_test(NAME enip_symbolic_write_tag_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip.pcap" --format text)
set_tests_properties(enip_symbolic_write_tag_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[enip\\]  SendRRData; Write_Tag request path=Pump1_Speed[^\n]*\n.*\\[enip\\]  SendRRData; Write_Tag response: Success")

add_test(NAME enip_unregister_session_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip.pcap" --format text)
set_tests_properties(enip_unregister_session_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[enip\\]  UnRegisterSession")

# Regression fixture for the NOP-exclusion fix (see enip_command_name's comment in enip.cpp and
# tests/real_captures/enip/ATTRIBUTION.md): an all-zero 24-byte buffer -- exactly what a NOP
# encapsulation message looks like on the wire -- sent on EtherNet/IP's own port must NOT be
# classified as enip.
add_test(NAME enip_nop_not_detected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_nop_precedence.pcap" --format text)
set_tests_properties(enip_nop_not_detected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[tcp\\]  TCP payload of 24 byte\\(s\\) on port 52001->44818 did not match EtherNet/IP, IEC 104, Modbus, DNP3, or COTP/S7comm")

# --------------------------------------------------------------------------
# EtherNet/IP CIP I/O (implicit messaging), synthetic (tests/sample_enip_cip_io.pcap): UDP/2222
# datagrams -- see tools/make_sample_pcap.py's build_enip_cip_io_sample for the exact byte layout
# each assertion below is checking, and enip.hpp's file header comment's CIP implicit messaging
# section for the decoder itself.
# --------------------------------------------------------------------------
add_test(NAME enip_cip_io_sequenced_address_and_data_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_cip_io.pcap" --format text)
set_tests_properties(enip_cip_io_sequenced_address_and_data_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[enip\\]  CIP I/O \\(implicit messaging\\): connection_id=0xABCD1234 sequence=1 data=4 byte\\(s\\)")

add_test(NAME enip_cip_io_sequence_rolls_between_datagrams
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_cip_io.pcap" --format text)
set_tests_properties(enip_cip_io_sequence_rolls_between_datagrams PROPERTIES
  PASS_REGULAR_EXPRESSION "connection_id=0xABCD1234 sequence=1[^\n]*\n.*connection_id=0xABCD1234 sequence=2")

add_test(NAME enip_cip_io_no_connected_data_item_worded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_cip_io.pcap" --format text)
set_tests_properties(enip_cip_io_no_connected_data_item_worded PROPERTIES
  PASS_REGULAR_EXPRESSION "connection_id=0xABCD1234 sequence=3 \\(no Connected Data Item present\\)")

add_test(NAME enip_cip_io_sockaddr_info_item_named_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_cip_io.pcap" --format text)
set_tests_properties(enip_cip_io_sockaddr_info_item_named_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "connection_id=0x11112222 sequence=10 data=1 byte\\(s\\)\n *note: CPF item 0x8001 \\(Sockaddr Info\\) present, not decoded")

add_test(NAME enip_cip_io_non_sequenced_address_first_item_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_cip_io.pcap" --format text)
set_tests_properties(enip_cip_io_non_sequenced_address_first_item_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 14 byte\\(s\\) on port 2222->2222")

add_test(NAME enip_cip_io_json_fields_populated
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_cip_io.pcap")
set_tests_properties(enip_cip_io_json_fields_populated PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"enip\",\n    \"summary\": \"CIP I/O \\(implicit messaging\\): connection_id=0xABCD1234 sequence=1 data=4 byte\\(s\\)\",\n    \"enip_io_connection_id\": \"0xABCD1234\",\n    \"enip_io_sequence_number\": 1,\n    \"enip_io_data_length\": 4,\n    \"enip_io_data_hex\": \"deadbeef\"")

add_test(NAME enip_cip_io_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_cip_io.pcap" --stats)
set_tests_properties(enip_cip_io_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "enip cip i/o \\(implicit messaging\\) datagrams: 4")

# --------------------------------------------------------------------------
# Real-world EtherNet/IP captures -- see tests/real_captures/enip/ATTRIBUTION.md for provenance.
# Both sourced from the ITI/ICS-Security-Tools public pcap collection: a real Rockwell 1756-ENBT/A
# ControlLogix bridge module's ListIdentity exchange, and a larger real industrial control system
# capture (trimmed for fixture size) dominated by Multiple_Service_Packet/Unconnected_Send/
# Read_Modify_Write_Tag traffic polling a vendor-specific object.
# --------------------------------------------------------------------------
set(ENIP_REAL_CAPTURES
  enip_list_identity
  ethernetip_cip_explicit_messaging
)
# Same baseline regression guard as the other protocols' real-capture loops above: must never
# crash the parser or exit non-zero, independent of what it does or doesn't manage to decode.
foreach(capture ${ENIP_REAL_CAPTURES})
  add_test(NAME real_enip_${capture}_does_not_crash
    COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/enip/${capture}.pcap" --format json)
endforeach()

# The ListIdentity capture: a real ControlLogix bridge module's identity response -- confirms the
# decoder against an independent device's actual wire encoding, not just the synthetic fixture's
# hand-constructed bytes.
add_test(NAME real_enip_list_identity_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/enip/enip_list_identity.pcap" --format text)
set_tests_properties(real_enip_list_identity_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[enip\\]  ListIdentity; identity: vendor=")

# The larger CIP explicit-messaging capture: real Multiple_Service_Packet / Unconnected_Send /
# Read_Modify_Write_Tag traffic -- confirms the recursive envelope decoding against real-world
# nesting, not just the synthetic fixture's single-level messages.
add_test(NAME real_enip_multiple_service_packet_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/enip/ethernetip_cip_explicit_messaging.pcap" --format text)
set_tests_properties(real_enip_multiple_service_packet_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Multiple_Service_Packet")

# --------------------------------------------------------------------------
# PROFINET RT (synthetic, tests/sample_profinet.pcap): DCP (Discovery and Configuration
# Protocol) request/response exchanges and cyclic real-time IO data frames -- see
# tools/make_sample_pcap.py's build_profinet_sample for the exact byte layout each assertion
# below is checking, and profinet.hpp's file header comment for the decoder itself. Unlike every
# other protocol above, PROFINET RT rides directly on raw Ethernet (EtherType 0x8892) -- there is
# no IP/TCP/UDP layer at all.
# --------------------------------------------------------------------------
add_test(NAME profinet_dcp_identify_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_dcp_identify_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[profinet\\]  DCP Identify Request xid=0x00112233")

add_test(NAME profinet_dcp_unknown_block_shown_as_raw_hex
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_dcp_unknown_block_shown_as_raw_hex PROPERTIES
  PASS_REGULAR_EXPRESSION "note: DCP block option=0xFF suboption=0xFF not decoded")

# The Identify Response: same Xid as the Request above (authoritative pairing isn't attempted by
# this decoder, but a matching Xid is still a useful correlation signal for a human reading the
# output), and all five of this decoder's value-decoded DCP block types in one PDU.
add_test(NAME profinet_dcp_identify_response_headline_fields_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_dcp_identify_response_headline_fields_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "DCP Identify Response-Success xid=0x00112233 name_of_station=\"plc-1\" vendor=0x002A device=0x0101")

# Regression guard for DCP block-list padding (see profinet.cpp's decode_dcp_blocks): the
# NameOfStation block above is a deliberately ODD-length string ("plc-1", 5 bytes); if the pad
# byte before the next block were handled wrong, DeviceID/DeviceRole below would misparse instead
# of decoding cleanly.
add_test(NAME profinet_dcp_response_all_blocks_decoded_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap")
set_tests_properties(profinet_dcp_response_all_blocks_decoded_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"profinet_dcp_blocks\": \\[\"MACAddress=00:0C:29:AA:BB:CC\", \"IPParameter=ip=192.168.1.10 subnet=255.255.255.0 gateway=192.168.1.1\", \"NameOfStation=plc-1\", \"DeviceID=vendor=0x002A device=0x0101\", \"DeviceRole=0x01 \\[IO Device\\]\"\\]")

add_test(NAME profinet_dcp_set_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_dcp_set_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[profinet\\]  DCP Set Request xid=0x00445566")

# Regression guard for the OTHER (ServiceID, direction) combination that carries a 2-byte prefix
# before an Option 0x01/0x02 block's content (BlockQualifier, for a Set Request -- see
# dcp_block_prefix_len's comment in profinet.cpp): if that prefix weren't stripped, this
# IPParameter block would show as an unrecognized 14-byte blob instead of decoding cleanly.
add_test(NAME profinet_dcp_set_request_block_qualifier_stripped
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap")
set_tests_properties(profinet_dcp_set_request_block_qualifier_stripped PROPERTIES
  PASS_REGULAR_EXPRESSION "\"profinet_dcp_blocks\": \\[\"IPParameter=ip=192.168.1.20 subnet=255.255.255.0 gateway=192.168.1.1\"\\]")

add_test(NAME profinet_dcp_hello_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_dcp_hello_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "DCP Hello Request xid=0x00998877 name_of_station=\"device-1\"")

add_test(NAME profinet_cyclic_unicast_healthy_status_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_cyclic_unicast_healthy_status_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Cyclic RT IO data \\(RT_CLASS_1, unicast\\): 8 byte\\(s\\) IO data, cycle_counter=4660 data_status=\\[Primary,Valid,Run,Ok\\] transfer_status=OK")

add_test(NAME profinet_cyclic_multicast_bad_status_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_cyclic_multicast_bad_status_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Cyclic RT IO data \\(RT_CLASS_1, multicast\\): 4 byte\\(s\\) IO data, cycle_counter=22136 data_status=\\[Backup,Invalid,Stop,Problem,Ignore\\] transfer_status=ignore this frame \\(0x01\\)")

add_test(NAME profinet_cyclic_empty_io_data_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_cyclic_empty_io_data_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "0 byte\\(s\\) IO data[^\n]*\n *note: no IO data present")

add_test(NAME profinet_alarm_high_named_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_alarm_high_named_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[profinet\\]  PROFINET RT: Alarm High \\(frame_id=0xFC01\\)")

add_test(NAME profinet_dcp_truncated_header_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_dcp_truncated_header_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: DCP PDU too short \\(3 byte\\(s\\)\\) for the fixed 10-byte header")

add_test(NAME profinet_cyclic_truncated_trailer_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_cyclic_truncated_trailer_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: cyclic RT frame too short \\(2 byte\\(s\\)\\) for the 4-byte CycleCounter/DataStatus/TransferStatus trailer")

# A reserved/unrecognized FrameID (0x1000) must NOT be misdetected as PROFINET -- falls through to
# the same generic "non-ip" ethertype-name-only report as any other 0x8892 traffic this decoder
# doesn't recognize (see tests/sample_link_transport_layers.pcap's own 0x8892 coverage).
add_test(NAME profinet_reserved_frame_id_falls_back_to_non_ip
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --format text)
set_tests_properties(profinet_reserved_frame_id_falls_back_to_non_ip PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-ip\\]  Ethernet frame with ethertype 0x8892 \\(PROFINET RT\\) \\(not IPv4\\)")

add_test(NAME profinet_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_profinet.pcap" --stats)
set_tests_properties(profinet_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "profinet dcp messages: 4\nprofinet cyclic rt io datagrams: 3")

# --------------------------------------------------------------------------
# Real-world PROFINET RT/DCP captures -- see tests/real_captures/profinet/ATTRIBUTION.md for
# provenance. Both sourced from the ITI/ICS-Security-Tools public pcap collection: fourteen real
# targeted DCP Identify Requests from a live segment, and a real Identify/Set exchange that
# caught a genuine decoding bug (a missing BlockInfo/BlockQualifier prefix -- see
# ATTRIBUTION.md's writeup and dcp_block_prefix_len's comment in profinet.cpp) before this
# feature ever shipped.
# --------------------------------------------------------------------------
set(PROFINET_REAL_CAPTURES
  profinet_rt_identify_requests
  profinet_change_ip_using_dcp
)
# Same baseline regression guard as the other protocols' real-capture loops above: must never
# crash the parser or exit non-zero, independent of what it does or doesn't manage to decode.
foreach(capture ${PROFINET_REAL_CAPTURES})
  add_test(NAME real_profinet_${capture}_does_not_crash
    COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/profinet/${capture}.pcap" --format json)
endforeach()

# The targeted-identify capture: several independent real devices' own FrameID/Xid/NameOfStation
# encodings, not just the synthetic fixture's hand-constructed bytes.
add_test(NAME real_profinet_identify_requests_named_stations_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/profinet/profinet_rt_identify_requests.pcap" --format text)
set_tests_properties(real_profinet_identify_requests_named_stations_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "DCP Identify Request xid=0x0300BF9A name_of_station=\"switch3\"")

# The bug-catching capture: confirms the BlockInfo-prefix fix against the real device's actual
# bytes -- if this regressed, name_of_station would go back to two leading NUL bytes and
# DeviceID/DeviceRole/IPParameter would go back to being undecoded.
add_test(NAME real_profinet_change_ip_identify_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/profinet/profinet_change_ip_using_dcp.pcap" --format text)
set_tests_properties(real_profinet_change_ip_identify_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "DCP Identify Response-Success xid=0x01000001 name_of_station=\"X208-BORD\" vendor=0x002A device=0x0A01")

add_test(NAME real_profinet_change_ip_set_request_ip_parameter_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/profinet/profinet_change_ip_using_dcp.pcap")
set_tests_properties(real_profinet_change_ip_set_request_ip_parameter_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"profinet_dcp_blocks\": \\[\"IPParameter=ip=192.168.0.10 subnet=255.255.255.0 gateway=192.168.0.1\"\\]")

# --------------------------------------------------------------------------
# IEC 61850-8-1 GOOSE (synthetic, tests/sample_goose.pcap): the ASN.1 BER-encoded GOOSE PDU and
# its recursive allData "Data" values -- see tools/make_sample_pcap.py's build_goose_sample for
# the exact byte layout each assertion below is checking, and goose.hpp's file header comment for
# the decoder itself. Like PROFINET RT, GOOSE rides directly on raw Ethernet (EtherType 0x88B8) --
# there is no IP/TCP/UDP layer at all.
# --------------------------------------------------------------------------
add_test(NAME goose_full_field_pdu_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_full_field_pdu_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[goose\\]  GOOSE IED1/LLN0\\$GO\\$gcb01 goID=\"gcb01\" stNum=1 sqNum=1 confRev=1")

add_test(NAME goose_optional_fields_absent_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_optional_fields_absent_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "GOOSE IED1/LLN0\\$GO\\$gcb02 stNum=1 sqNum=1 confRev=1\n")

add_test(NAME goose_header_sbit_simulation_mismatch_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_header_sbit_simulation_mismatch_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "gcb03.*\\[SIMULATED\\][^\n]*\n *note: header S-bit \\(Reserved1 0x8000, \"Simulated\"\\) is set but the PDU's own simulation field is false")

# The S-bit and the PDU's own simulation field are BOTH true here -- consistent, so no mismatch
# note should appear (a regression here would mean the mismatch check fires on every simulated
# frame, not just an inconsistent one).
add_test(NAME goose_header_sbit_simulation_consistent_no_mismatch_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_header_sbit_simulation_consistent_no_mismatch_note PROPERTIES
  PASS_REGULAR_EXPRESSION "gcb04.*\\[SIMULATED\\]\n"
  FAIL_REGULAR_EXPRESSION "gcb04[^\n]*\n *note: header S-bit")

# allData Data-choice types no real capture checked ever exercised (see tests/real_captures/goose/
# ATTRIBUTION.md's "gaps" section): integer (negative, sign-extension), unsigned, bcd,
# floating-point single AND double precision, octet-string, visible-string, mMSString, utc-time.
add_test(NAME goose_all_data_type_diversity_decoded_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap")
set_tests_properties(goose_all_data_type_diversity_decoded_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "0: integer=-5.*1: unsigned=70000.*2: bcd=42.*3: floating-point=3.5f \\(single precision\\).*4: floating-point=-2.25 \\(double precision\\).*5: octet-string=de ad be ef.*6: visible-string=hello.*7: mMSString=world.*8: utc-time=946781171")

add_test(NAME goose_utc_time_data_value_quality_bits_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap")
set_tests_properties(goose_utc_time_data_value_quality_bits_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "utc-time=946781171.500000000s accuracy=7-bit \\[ClockNotSynchronized\\]")

# Nested structure (a boolean + an integer) followed by a nested array (two floats) -- exercises
# decode_data_sequence's recursion, the dotted "N.M" path scheme, and the container-entry's own
# rendered child count.
add_test(NAME goose_nested_structure_array_decoded_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap")
set_tests_properties(goose_nested_structure_array_decoded_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "0: structure=\\(2 flattened value\\(s\\) follow\\).*0.0: boolean=true.*0.1: integer=7.*1: array=\\(2 flattened value\\(s\\) follow\\).*1.0: floating-point=1.5f \\(single precision\\).*1.1: floating-point=2.5f \\(single precision\\)")

# Types this decoder names but deliberately never value-decodes (real/binary-time/objId) show as
# raw hex WITHOUT a note (they're recognized, just out of scope); the one truly unrecognized tag
# (0x95) shows as raw hex AND triggers a "tag not recognized" note.
add_test(NAME goose_named_but_not_decoded_data_types_shown_as_raw_hex
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap")
set_tests_properties(goose_named_but_not_decoded_data_types_shown_as_raw_hex PROPERTIES
  PASS_REGULAR_EXPRESSION "0: real=01 02 03.*1: binary-time=00 00 00 01.*2: objId=28 01 02.*3: raw=ff ee")

add_test(NAME goose_unrecognized_data_tag_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_unrecognized_data_tag_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: allData\\[3\\]: tag not recognized -- raw hex: ff ee")

add_test(NAME goose_num_dat_set_entries_mismatch_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_num_dat_set_entries_mismatch_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: numDatSetEntries declares 5 but 2 top-level Data value\\(s\\) were actually found in allData")

add_test(NAME goose_gse_management_named_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_gse_management_named_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[goose\\]  GOOSE: GSE Management PDU \\(appid=0x2000\\) -- not decoded further")

add_test(NAME goose_vlan_tagged_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_vlan_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "GOOSE IED3/LLN0\\$GO\\$gcb10 stNum=1 sqNum=1 confRev=1")

# A GOOSE frame too short for even the fixed 8-byte APPID/Length/Reserved1/Reserved2 header must
# NOT be misdetected -- falls through to the generic "non-ip" ethertype-name-only report, same as
# tests/sample_link_transport_layers.pcap's own 0x88B8 coverage.
add_test(NAME goose_truncated_header_falls_back_to_non_ip
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_truncated_header_falls_back_to_non_ip PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-ip\\]  Ethernet frame with ethertype 0x88b8 \\(IEC 61850-8-1 GOOSE\\) \\(not IPv4\\)")

add_test(NAME goose_bogus_length_field_falls_back_to_available_bytes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_bogus_length_field_falls_back_to_available_bytes PROPERTIES
  PASS_REGULAR_EXPRESSION "GOOSE IED4/LLN0\\$GO\\$gcb13[^\n]*\n *note: Length field \\(3\\) is implausible")

add_test(NAME goose_truncated_apdu_partial_decode_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --format text)
set_tests_properties(goose_truncated_apdu_partial_decode_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "GOOSE IED5/LLN0\\$GO\\$gcb14[^\n]*\n *note: GOOSE APDU declares 200 byte\\(s\\) but only 20 remain -- decoding what's present")

add_test(NAME goose_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_goose.pcap" --stats)
set_tests_properties(goose_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "goose pdus: 11\ngoose gse management pdus \\(not decoded further\\): 1\ngoose simulated \\(S-bit or simulation field set\\): 2")

# --------------------------------------------------------------------------
# Real-world IEC 61850-8-1 GOOSE captures -- see tests/real_captures/goose/ATTRIBUTION.md for
# provenance. All four sourced from the same ITI/ICS-Security-Tools public pcap collection
# PROFINET RT's real fixtures came from: a GE F650 relay's own retransmission/sqNum-reset
# sequence, a single maximally-complete VLAN-tagged frame, a 451-frame bulk-validation capture,
# and a mixed MMS+GOOSE capture used as a crash-safety/non-interference check.
# --------------------------------------------------------------------------
set(GOOSE_REAL_CAPTURES
  goose_ge_f650_retransmissions
  goose_demo_full_fields
  sample_file_goose
  sample_file_mms_and_goose
)
# Same baseline regression guard as the other protocols' real-capture loops above: must never
# crash the parser or exit non-zero, independent of what it does or doesn't manage to decode.
foreach(capture ${GOOSE_REAL_CAPTURES})
  add_test(NAME real_goose_${capture}_does_not_crash
    COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/goose/${capture}.pcap" --format json)
endforeach()

# The F650 relay capture: sqNum counts 10, 11, 12 then RESETS to 1 while stNum stays at 1 -- a
# publisher restart/re-enable mid-capture, the real-world shape stNum/sqNum are meant to follow
# (see goose.hpp's file header comment).
add_test(NAME real_goose_f650_sqnum_sequence_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/goose/goose_ge_f650_retransmissions.pcap" --format text)
set_tests_properties(real_goose_f650_sqnum_sequence_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "sqNum=10[^\n]*\n[^\n]*sqNum=11[^\n]*\n[^\n]*sqNum=12[^\n]*\n[^\n]*sqNum=1 ")

add_test(NAME real_goose_demo_full_fields_vlan_and_multi_byte_integer_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/goose/goose_demo_full_fields.pcap")
set_tests_properties(real_goose_demo_full_fields_vlan_and_multi_byte_integer_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"goose_gocb_ref\": \"111\".*\"goose_go_id\": \"333\".*\"goose_num_dat_set_entries\": 10")

add_test(NAME real_goose_sample_file_bulk_zero_notes
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/goose/sample_file_goose.pcap")
set_tests_properties(real_goose_sample_file_bulk_zero_notes PROPERTIES
  PASS_REGULAR_EXPRESSION "\"goose_gocb_ref\": \"AA1C1Q01A1LD0/LLN0\\$GO\\$gcb_A\""
  FAIL_REGULAR_EXPRESSION "\"notes\": \\[\"")

add_test(NAME real_goose_mms_and_goose_mixed_protocols_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/goose/sample_file_mms_and_goose.pcap" --stats)
set_tests_properties(real_goose_mms_and_goose_mixed_protocols_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "cotp[^\n]*\n *goose +34")

# --------------------------------------------------------------------------
# IEC 61850-9-2 Sampled Values (synthetic, tests/sample_sv.pcap): the ASN.1 BER-encoded SavPdu
# (noASDU + one or more ASDU elements) -- see tools/make_sample_pcap.py's build_sv_sample for the
# exact byte layout each assertion below is checking, and sv.hpp's file header comment for the
# decoder itself. Like GOOSE and PROFINET RT, SV rides directly on raw Ethernet (EtherType
# 0x88BA) -- there is no IP/TCP/UDP layer at all. No real SV capture was found despite a genuine
# search (see sv.hpp's Validation paragraph), so unlike GOOSE, there is no real-capture test block
# below -- every path here is synthetic-only.
# --------------------------------------------------------------------------
add_test(NAME sv_full_field_asdu_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap")
set_tests_properties(sv_full_field_asdu_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"sv_id\": \"IED1/MSVCB01\".*\"sv_dat_set\": \"IED1/LLN0\\$MEAS1\".*\"sv_smp_cnt\": 1234.*\"sv_conf_rev\": 1.*\"sv_smp_synch\": \"global\".*\"sv_smp_rate\": 4000.*\"sv_smp_mod\": \"samplesPerNormalPeriod\".*\"sv_seq_data_length\": 64.*\"sv_gmid_hex\": \"0019fbfffe001122\"")

add_test(NAME sv_optional_fields_absent_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_optional_fields_absent_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "SV IED1/MSVCB02 smpCnt=5678 confRev=1\n")

# Two ASDUs in one seqASDU -- exercises the SEQUENCE OF ASDU decode, the frame summary's "(+N more
# ASDU(s))" suffix, and sv_asdus carrying one entry per ASDU.
add_test(NAME sv_multiple_asdus_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap")
set_tests_properties(sv_multiple_asdus_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"sv_asdu_count\": 2.*\"sv_asdus\": \\[\"svID=\\\\\"IED2/MSVCB01\\\\\"[^\"]*smpSynch=local[^\"]*\", \"svID=\\\\\"IED2/MSVCB02\\\\\"[^\"]*smpSynch=none")

add_test(NAME sv_multiple_asdus_summary_suffix
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_multiple_asdus_summary_suffix PROPERTIES
  PASS_REGULAR_EXPRESSION "SV IED2/MSVCB01 smpCnt=100 confRev=3 smpSynch=local \\(\\+1 more ASDU\\(s\\)\\)")

# Header S-bit set -- SV has no PDU-level simulation field to cross-check against (unlike GOOSE),
# so this is simply sv_simulated=true with no consistency note.
add_test(NAME sv_header_sbit_simulated
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap")
set_tests_properties(sv_header_sbit_simulated PROPERTIES
  PASS_REGULAR_EXPRESSION "\"sv_simulated\": true.*\"sv_id\": \"IED1/MSVCB04\"")

add_test(NAME sv_unrecognized_smp_synch_and_smp_mod_rendered_as_unknown
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap")
set_tests_properties(sv_unrecognized_smp_synch_and_smp_mod_rendered_as_unknown PROPERTIES
  PASS_REGULAR_EXPRESSION "\"sv_id\": \"IED1/MSVCB05\".*\"sv_smp_synch\": \"unknown\\(5\\)\".*\"sv_smp_mod\": \"unknown\\(5\\)\"")

add_test(NAME sv_smp_mod_samples_per_second_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap")
set_tests_properties(sv_smp_mod_samples_per_second_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"sv_id\": \"IED1/MSVCB06\".*\"sv_smp_mod\": \"samplesPerSecond\"")

add_test(NAME sv_smp_mod_seconds_per_sample_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap")
set_tests_properties(sv_smp_mod_seconds_per_sample_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"sv_id\": \"IED1/MSVCB07\".*\"sv_smp_mod\": \"secondsPerSample\"")

add_test(NAME sv_no_asdu_mismatch_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_no_asdu_mismatch_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: noASDU declares 3 but 2 ASDU\\(s\\) were actually found in seqASDU")

add_test(NAME sv_vlan_tagged_multicast_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_vlan_tagged_multicast_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "SV IED4/MSVCB01 smpCnt=1 confRev=1")

# An SV frame too short for even the fixed 8-byte APPID/Length/Reserved1/Reserved2 header must NOT
# be misdetected -- falls through to the generic "non-ip" ethertype-name-only report.
add_test(NAME sv_truncated_header_falls_back_to_non_ip
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_truncated_header_falls_back_to_non_ip PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-ip\\]  Ethernet frame with ethertype 0x88ba \\(IEC 61850-9-2 Sampled Values\\) \\(not IPv4\\)")

# A full 8-byte header but the byte immediately after it is not 0x60 -- must NOT be misdetected as
# SV; both this packet and the truncated-header one above fall back to the same "non-ip" report,
# so this asserts there are exactly two such lines in the whole file (no false positive elsewhere).
add_test(NAME sv_wrong_outer_tag_falls_back_to_non_ip
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_wrong_outer_tag_falls_back_to_non_ip PROPERTIES
  PASS_REGULAR_EXPRESSION "non-ip\\][^\n]*\n#11[^\n]*non-ip\\]")

add_test(NAME sv_bogus_length_field_falls_back_to_available_bytes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_bogus_length_field_falls_back_to_available_bytes PROPERTIES
  PASS_REGULAR_EXPRESSION "SV IED5/MSVCB01 smpCnt=1 confRev=1[^\n]*\n *note: Length field \\(3\\) is implausible")

add_test(NAME sv_truncated_apdu_partial_decode_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_truncated_apdu_partial_decode_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "SV appid=0x4009 noASDU=1 \\(0 ASDU\\(s\\) decoded\\)[^\n]*\n *note: SV APDU declares 200 byte\\(s\\) but only 3 remain -- decoding what's present")

add_test(NAME sv_wrong_asdu_element_tag_skipped_with_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_wrong_asdu_element_tag_skipped_with_note PROPERTIES
  PASS_REGULAR_EXPRESSION "note: seqASDU element tag=0x31 is not the expected UNIVERSAL SEQUENCE tag \\(0x30\\) -- skipped")

add_test(NAME sv_unrecognized_asdu_field_tag_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_unrecognized_asdu_field_tag_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "SV IED6/MSVCB01 smpCnt=1 confRev=1[^\n]*\n *note: unrecognized ASDU field tag=0x8F len=2 -- skipped, raw hex: aa bb")

add_test(NAME sv_unrecognized_sav_pdu_field_tag_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --format text)
set_tests_properties(sv_unrecognized_sav_pdu_field_tag_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "SV IED7/MSVCB01 smpCnt=1 confRev=1[^\n]*\n *note: unrecognized SavPdu field tag=0x81 len=1 -- skipped, raw hex: 00")

add_test(NAME sv_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_sv.pcap" --stats)
set_tests_properties(sv_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "sv frames: 14\nsv asdus \\(summed across every frame\\): 14")

# --------------------------------------------------------------------------
# EtherCAT (synthetic, tests/sample_ethercat.pcap): the 2-byte frame header (Length+Reserved+Type)
# and, for Type 1 ("EtherCAT command") frames, the chained EtherCAT datagram(s) that follow -- see
# tools/make_sample_pcap.py's build_ethercat_sample for the exact byte layout each assertion below
# is checking, and ethercat.hpp's file header comment for the decoder itself. Like PROFINET RT/
# GOOSE/SV, EtherCAT rides directly on raw Ethernet (EtherType 0x88A4) -- there is no IP/TCP/UDP
# layer at all, and unlike those three, its wire format is plain fixed-binary, not ASN.1/BER.
# --------------------------------------------------------------------------
add_test(NAME ethercat_baseline_brd_matches_real_capture_frame_zero
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_baseline_brd_matches_real_capture_frame_zero PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[ethercat\\]  ECAT BRD idx=2 adp=0x0000 ado=0x0130 len=2 wkc=0\n")

add_test(NAME ethercat_chained_topology_discovery_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_chained_topology_discovery_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT APRD idx=10 adp=0x0000 ado=0x0130 len=2 wkc=1 \\(\\+4 more datagram\\(s\\)\\)")

add_test(NAME ethercat_chained_topology_discovery_auto_increment_addresses_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap")
set_tests_properties(ethercat_chained_topology_discovery_auto_increment_addresses_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ethercat_datagram_count\": 5.*\"ethercat_datagrams\": \\[\"APRD idx=10 adp=0x0000[^\"]*\", \"APRD idx=11 adp=0xFFFF[^\"]*\", \"APRD idx=12 adp=0xFFFE[^\"]*\", \"APRD idx=13 adp=0xFFFD[^\"]*\", \"APRD idx=14 adp=0xFFFC[^\"]*\"\\]")

add_test(NAME ethercat_logical_addressing_lrd_lwr_lrw_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_logical_addressing_lrd_lwr_lrw_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT LRD idx=20 logAddr=0x00010000 len=4 wkc=1\n.*ECAT LWR idx=21 logAddr=0x00020000 len=4 wkc=1\n.*ECAT LRW idx=22 logAddr=0x00030000 len=4 wkc=3\n")

add_test(NAME ethercat_logical_address_promoted_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap")
set_tests_properties(ethercat_logical_address_promoted_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ethercat_first_cmd_name\": \"LRD\".*\"ethercat_first_logical_address\": 65536")

# Cmd values the real capture (tests/real_captures/ethercat/ATTRIBUTION.md) does NOT exercise --
# APRW/FPRW/BRW (ReadWrite variants), ARMW/FRMW (Read Multiple Write), EXT, and NOP -- one datagram
# each, all decoded structurally via the ordinary Adp+Ado default addressing case.
add_test(NAME ethercat_cmd_values_not_in_real_capture_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_cmd_values_not_in_real_capture_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT APRW idx=30[^\n]*\n.*ECAT FPRW idx=31[^\n]*\n.*ECAT BRW idx=32[^\n]*\n.*ECAT ARMW idx=33[^\n]*\n.*ECAT FRMW idx=34[^\n]*\n.*ECAT EXT idx=35[^\n]*\n.*ECAT NOP idx=36 adp=0x0000 ado=0x0000 len=0 wkc=0\n")

add_test(NAME ethercat_unrecognized_cmd_rendered_as_unknown
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_unrecognized_cmd_rendered_as_unknown PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT unknown\\(200\\) idx=40 adp=0x0005 ado=0x0100 len=2 wkc=0")

# Len word's Circulating bit (0x4000) -- never observed set in the real capture (see
# ATTRIBUTION.md), synthetic-only. Surfaced via ethercat_first_circulating and the per-datagram
# summary's " circulating" suffix, not the terse top-level frame summary (matching how GOOSE's own
# S-bit is surfaced in JSON/notes rather than its one-line summary).
add_test(NAME ethercat_circulating_bit_decoded_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap")
set_tests_properties(ethercat_circulating_bit_decoded_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ethercat_first_idx\": 41.*\"ethercat_first_circulating\": true.*\"ethercat_datagrams\": \\[\"FPRD idx=41[^\"]* circulating\"\\]")

add_test(NAME ethercat_frame_header_reserved_bit_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_frame_header_reserved_bit_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT FPRD idx=42[^\n]*\n *note: frame header Reserved bit is set -- the spec says this must be zero")

add_test(NAME ethercat_wkc_zero_anomaly_surfaced_raw
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_wkc_zero_anomaly_surfaced_raw PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT BWR idx=43 adp=0x0000 ado=0x0130 len=2 wkc=0\n")

# Frame Types 2-5 (ADS/RAW-IO/NV/Mailbox) -- named only, not decoded further, the same "named only"
# pattern goose.hpp's GSE Management PDU and profinet.hpp's non-cyclic FrameID ranges already use.
add_test(NAME ethercat_frame_types_2_to_5_named_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_frame_types_2_to_5_named_only PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT type=ADS \\(not decoded further\\)\n.*ECAT type=RAW-IO \\(not decoded further\\)\n.*ECAT type=NV \\(not decoded further\\)\n.*ECAT type=Mailbox \\(not decoded further\\)")

# A genuinely unrecognized/reserved frame header Type value (0) -- must NOT be misdetected as
# EtherCAT at all; falls back to the generic "non-ip" ethertype-name-only report -- see
# ethercat.hpp's "structural detection gate" paragraph.
add_test(NAME ethercat_unrecognized_type_falls_back_to_non_ip
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_unrecognized_type_falls_back_to_non_ip PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-ip\\]  Ethernet frame with ethertype 0x88a4 \\(EtherCAT\\) \\(not IPv4\\)")

# 802.1Q VLAN-priority-tagged EtherCAT -- confirms parse_ethernet's single-VLAN-tag unwrap composes
# correctly with EtherCAT detection, mirroring GOOSE/SV's own VLAN tests.
add_test(NAME ethercat_vlan_tagged_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_vlan_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT BRD idx=44 adp=0x0000 ado=0x0130 len=2 wkc=1")

# An EtherCAT frame too short for even the fixed 2-byte frame header must NOT be misdetected --
# falls through to the generic "non-ip" ethertype-name-only report. Both this packet and the
# unrecognized-Type one above fall back to the same "non-ip" report, so this asserts there are
# exactly two such lines in the whole file (no false positive elsewhere).
add_test(NAME ethercat_truncated_header_falls_back_to_non_ip
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_truncated_header_falls_back_to_non_ip PROPERTIES
  PASS_REGULAR_EXPRESSION "non-ip\\][^\n]*\n.*#23[^\n]*non-ip\\]")

add_test(NAME ethercat_bogus_length_field_falls_back_to_available_bytes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_bogus_length_field_falls_back_to_available_bytes PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT BRD idx=45 adp=0x0000 ado=0x0130 len=2 wkc=1[^\n]*\n *note: frame header Length \\(0\\) is implausible")

add_test(NAME ethercat_more_bit_set_on_last_datagram_truncation_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_more_bit_set_on_last_datagram_truncation_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT APRD idx=46[^\n]*\n *note: EtherCAT datagram chain: More bit set on the last datagram decoded, but no bytes remain")

add_test(NAME ethercat_partial_datagram_header_truncation_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_partial_datagram_header_truncation_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT 0 datagram\\(s\\) decoded[^\n]*\n *note: EtherCAT datagram header needs 10 byte\\(s\\) but only 5 remain -- chain truncated, stopping")

add_test(NAME ethercat_safety_cap_stops_at_200_datagrams
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --format text)
set_tests_properties(ethercat_safety_cap_stops_at_200_datagrams PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT NOP idx=0 adp=0x0000 ado=0x0000 len=0 wkc=0 \\(\\+199 more datagram\\(s\\)\\)[^\n]*\n *note: frame header Length \\(0\\) is implausible[^\n]*\n *note: EtherCAT datagram chain: stopped after 200 datagram\\(s\\) \\(safety cap\\)")

add_test(NAME ethercat_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ethercat.pcap" --stats)
set_tests_properties(ethercat_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "ethercat frame types:\n *ADS +1\n *EtherCAT command +21\n *Mailbox +1\n *NV +1\n *RAW-IO +1\nethercat datagrams \\(summed across every frame\\): 223")

# --------------------------------------------------------------------------
# Real-world EtherCAT captures -- see tests/real_captures/ethercat/ATTRIBUTION.md for provenance
# (a public mirror of the same file `automayt/ICS-pcap` stores via Git LFS, confirmed identical by
# SHA256). 986 frames, a master's boot-time slave enumeration and register poll sequence.
# --------------------------------------------------------------------------
add_test(NAME real_ethercat_ics_ethercat_001_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/ethercat/ICS-Ethercat-001.pcap" --format json)

add_test(NAME real_ethercat_frame_zero_matches_synthetic_baseline
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/ethercat/ICS-Ethercat-001.pcap" --format text)
set_tests_properties(real_ethercat_frame_zero_matches_synthetic_baseline PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[ethercat\\]  ECAT BRD idx=2 adp=0x0000 ado=0x0130 len=2 wkc=0\n")

# Every one of the 986 real frames is Type 1 with zero notes -- in particular, zero declared-Length-
# vs-actual-chained-bytes mismatches (see ethercat.hpp's "declared Length" paragraph and
# ATTRIBUTION.md), zero Reserved-bit warnings, zero truncated-chain warnings.
add_test(NAME real_ethercat_stats_all_type1_zero_notes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/ethercat/ICS-Ethercat-001.pcap" --stats)
set_tests_properties(real_ethercat_stats_all_type1_zero_notes PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +986[^\n]*\n[^\n]*\nprotocols:\n *ethercat +986\nethercat frame types:\n *EtherCAT command +986\nethercat datagrams \\(summed across every frame\\): 8140")

add_test(NAME real_ethercat_no_notes_anywhere_in_capture
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/ethercat/ICS-Ethercat-001.pcap" --format text)
set_tests_properties(real_ethercat_no_notes_anywhere_in_capture PROPERTIES
  FAIL_REGULAR_EXPRESSION "note:")

# Auto-increment topology-discovery pattern (Adp 0x0000, then 0xFFFF, 0xFFFE, ...) -- see
# ethercat.hpp's "Auto increment addressing" paragraph -- appears in this real capture's early
# frames.
add_test(NAME real_ethercat_auto_increment_topology_discovery_pattern
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/ethercat/ICS-Ethercat-001.pcap" --format text)
set_tests_properties(real_ethercat_auto_increment_topology_discovery_pattern PROPERTIES
  PASS_REGULAR_EXPRESSION "ECAT BRD idx=2 adp=0x0000 ado=0x0130 len=2 wkc=0\n.*ECAT BRD idx=2 adp=0x0005 ado=0x0130 len=2 wkc=5\n")

add_test(NAME real_ethercat_logical_addressing_lrd_lwr_present
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/ethercat/ICS-Ethercat-001.pcap")
set_tests_properties(real_ethercat_logical_addressing_lrd_lwr_present PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ethercat_first_cmd_name\": \"LRD\"")

# --------------------------------------------------------------------------
# BACnet/IP (synthetic, tests/sample_bacnet.pcap): BVLC framing, NPDU network layer, APDU
# application layer/services over UDP port 47808 -- see tools/make_sample_pcap.py's
# build_bacnet_sample for the exact byte layout each assertion below is checking (packet numbers
# in comments match that function's own numbered comments 1-53), and bacnet.hpp's file header
# comment for the decoder itself. Unlike EtherCAT/GOOSE/SV/PROFINET, BACnet/IP rides over UDP, so
# detection is a payload-shape gate (BVLC Type 0x81 + Function 0x00-0x0C) applied port-
# independently, mirroring CIP I/O's own opportunistic detection.
# --------------------------------------------------------------------------

# 1-2) Who-Is, unrestricted and with a device-instance range.
add_test(NAME bacnet_who_is_unrestricted_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_who_is_unrestricted_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[bacnet\\]  BVLC Original-Broadcast-NPDU Unconfirmed-Request who-Is\n")

add_test(NAME bacnet_who_is_with_range_decoded_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_who_is_with_range_decoded_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_service_name\": \"who-Is\".*\"bacnet_values\": \\[\"device-instance-range-low=100\", \"device-instance-range-high=200\"\\]")

# 3) I-Am -- device object-identifier, Max-APDU-Length-Accepted, Segmentation-Supported, Vendor-ID.
add_test(NAME bacnet_i_am_all_four_fields_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_i_am_all_four_fields_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_service_name\": \"i-Am\".*\"bacnet_values\": \\[\"device-object=device,1234\", \"max-apdu-length-accepted=1476\", \"segmentation-supported=no-segmentation\", \"vendor-id=260\"\\]")

# 4-5) Who-Has, both CHOICE branches (by ObjectIdentifier-with-range, and by ObjectName).
add_test(NAME bacnet_who_has_by_object_identifier_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_who_has_by_object_identifier_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "who-Has \\[device-instance-range-low=1 \\+2 more\\]")

add_test(NAME bacnet_who_has_by_object_name_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_who_has_by_object_name_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_values\": \\[\"object-name=ZN-T-1\"\\]")

# 6) I-Have -- device id + object id + object name.
add_test(NAME bacnet_i_have_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_i_have_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_service_name\": \"i-Have\".*\"bacnet_values\": \\[\"device=device,1234\", \"object=analog-input,3\", \"object-name=ZN-T-1\"\\]")

# 7-14) ReadProperty request + ACKs covering every primitive PropertyValue type this decoder
# handles: Real, Unsigned, Enumerated, Boolean, CharacterString, BitString, and a propertyArrayIndex.
add_test(NAME bacnet_read_property_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_read_property_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Confirmed-Request invoke-id=10 readProperty \\[object=analog-input,3 \\+1 more\\]")

add_test(NAME bacnet_read_property_ack_real_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_read_property_ack_real_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_invoke_id\": 10.*\"bacnet_values\": \\[\"object=analog-input,3\", \"property=present-value\", \"value=\\(Real\\) 72.500000\"\\]")

add_test(NAME bacnet_read_property_ack_unsigned_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_read_property_ack_unsigned_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_invoke_id\": 11.*\"object=multi-state-input,1\".*\"value=\\(Unsigned Integer\\) 3\"")

add_test(NAME bacnet_read_property_ack_enumerated_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_read_property_ack_enumerated_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_invoke_id\": 12.*\"object=binary-input,1\".*\"value=\\(Enumerated\\) 1\"")

add_test(NAME bacnet_read_property_ack_boolean_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_read_property_ack_boolean_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_invoke_id\": 13.*\"value=\\(Boolean\\) FALSE\"")

add_test(NAME bacnet_read_property_ack_character_string_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_read_property_ack_character_string_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_invoke_id\": 14.*\"value=\\(Character String\\) ZN-T-1\"")

add_test(NAME bacnet_read_property_ack_bit_string_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_read_property_ack_bit_string_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_invoke_id\": 15.*\"value=\\(Bit String\\)")

add_test(NAME bacnet_read_property_ack_array_index_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_read_property_ack_array_index_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_invoke_id\": 16.*\"bacnet_values\": \\[\"object=analog-input,3\", \"property=present-value\", \"property-array-index=0\", \"value=\\(Real\\) 1.000000\"\\]")

# 15) A constructed (array/list-shaped) PropertyValue -- not a single primitive, so this decoder's
# first pass does not value-decode it, only notes as much -- see bacnet.hpp's "Property value
# decode" paragraph.
add_test(NAME bacnet_read_property_ack_constructed_value_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_read_property_ack_constructed_value_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "invoke-id=17 readProperty \\[object=analog-input,3 \\+1 more\\]\n *note: property value is constructed \\(an array/list or service-specific structured value\\), not a single primitive -- not value-decoded in this first-pass release")

# 16-17) WriteProperty, without and with the optional Priority field (context[4]).
add_test(NAME bacnet_write_property_no_priority_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_write_property_no_priority_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_service_name\": \"writeProperty\".*\"bacnet_invoke_id\": 20.*\"bacnet_values\": \\[\"object=binary-output,5\", \"property=present-value\", \"value=\\(Enumerated\\) 1\"\\]")

add_test(NAME bacnet_write_property_with_priority_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_write_property_with_priority_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_invoke_id\": 21.*\"bacnet_values\": \\[\"object=binary-output,5\", \"property=present-value\", \"value=\\(Enumerated\\) 0\", \"priority=8\"\\]")

# 18) Simple-ACK.
add_test(NAME bacnet_simple_ack_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_simple_ack_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Simple-ACK invoke-id=20 writeProperty\n")

# 19) Generic Error PDU shape (errorClass/errorCode).
add_test(NAME bacnet_generic_error_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_generic_error_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Error invoke-id=22 readProperty property/unknown-property\n")

# 20) Error PDU whose error-choice defines its OWN service-specific error structure -- named but
# shown as raw hex with an explanatory note, not misdecoded as the generic shape.
add_test(NAME bacnet_service_specific_error_not_misdecoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_service_specific_error_not_misdecoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Error invoke-id=23 writePropertyMultiple\n *note: error-choice writePropertyMultiple may use a service-specific error structure rather than the generic errorClass/errorCode shape this decoder decodes -- see bacnet.hpp")

# 21-23) Reject and Abort (both server=false and server=true).
add_test(NAME bacnet_reject_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_reject_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Reject invoke-id=24 unrecognized-service\n")

add_test(NAME bacnet_abort_client_and_server_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_abort_client_and_server_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Abort invoke-id=25 other\n.*Abort invoke-id=26 out-of-resources\n")

# 24-25) Segment-ACK, ordinary and negative/server.
add_test(NAME bacnet_segment_ack_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_segment_ack_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Segment-ACK invoke-id=27\n.*Segment-ACK invoke-id=28\n")

# 26-27) Segmented Confirmed-Request/Complex-ACK -- header fields decoded, service data left as
# raw hex with an explanatory note (no cross-packet reassembly). service_choice 14
# (readPropertyMultiple) doubles as an "outside the first-pass value-decode set" example.
add_test(NAME bacnet_segmented_apdu_not_value_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_segmented_apdu_not_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "invoke-id=30 readPropertyMultiple\n *note: segmented APDU:[^\n]*\n.*invoke-id=31 readPropertyMultiple\n *note: segmented APDU:")

add_test(NAME bacnet_segmented_flag_true_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_segmented_flag_true_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_invoke_id\": 30.*\"bacnet_segmented\": true")

# 28-29) A confirmed and an unconfirmed service outside the "first pass" value-decode set -- named
# via the service-choice table, data not value-decoded.
add_test(NAME bacnet_out_of_scope_services_named_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_out_of_scope_services_named_only PROPERTIES
  PASS_REGULAR_EXPRESSION "Confirmed-Request invoke-id=32 subscribeCOV\n.*Unconfirmed-Request unconfirmedCOVNotification\n")

# 30-33) NPDU DEST/SRC/both -- DNET/DLEN/DADR, SNET/SLEN/SADR, HopCount.
add_test(NAME bacnet_npdu_dest_present_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_npdu_dest_present_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_npdu_has_dest\": true,.*\"bacnet_npdu_dnet\": 5,.*\"bacnet_npdu_hop_count\": 255")

# DLEN/DADR themselves (6-byte MAC vs. DLEN=0 broadcast-on-destination-network) aren't promoted to
# DecodedPacket/JSON -- npdu.dadr_hex only ever reaches the (currently unused-in-JSON) NPDU struct
# field -- so packets #30 and #31 (ordinary 6-byte DADR vs. DLEN=0 broadcast) are only
# distinguishable from each other via full-frame internals this decoder doesn't yet surface; both
# still decode as ordinary DEST-present NPDUs with no notes, which this asserts by requiring the
# dnet=5 shape to appear twice.
add_test(NAME bacnet_npdu_dest_present_both_dadr_shapes_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_npdu_dest_present_both_dadr_shapes_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_npdu_dnet\": 5,.*\"bacnet_npdu_dnet\": 5,")

add_test(NAME bacnet_npdu_src_present_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_npdu_src_present_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_npdu_has_src\": true,.*\"bacnet_npdu_snet\": 7,.*\"device-object=device,999\"")

add_test(NAME bacnet_npdu_dest_and_src_both_present_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap")
set_tests_properties(bacnet_npdu_dest_and_src_both_present_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"bacnet_npdu_has_dest\": true,.*\"bacnet_npdu_dnet\": 5,.*\"bacnet_npdu_has_src\": true,.*\"bacnet_npdu_snet\": 7")

# 34-35) Network Layer Message -- named message type, and vendor-proprietary with its Vendor ID.
add_test(NAME bacnet_network_layer_message_named
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_network_layer_message_named PROPERTIES
  PASS_REGULAR_EXPRESSION "Network-Layer-Message Who-Is-Router-To-Network\n")

add_test(NAME bacnet_network_layer_message_vendor_proprietary_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_network_layer_message_vendor_proprietary_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Network-Layer-Message vendor-proprietary\\(128\\)\n")

# 36) BVLC-Result -- no NPDU at all, result code surfaced in both summary and notes (the bug this
# project's manual fixture review caught -- see the session's own record of the fix).
add_test(NAME bacnet_bvlc_result_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_bvlc_result_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "BVLC BVLC-Result result-code=0x0\n *note: result-code=0x0")

# 37-39) Write-BDT / Read-BDT / Read-BDT-Ack -- 10-byte-entry (IP+Port+Mask) BBMD tables.
add_test(NAME bacnet_write_bdt_entries_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_write_bdt_entries_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "BVLC Write-Broadcast-Distribution-Table \\(2 entry/entries\\)\n *note: 2 table entry/entries: 192\\.168\\.1\\.1:47808 mask=255\\.255\\.255\\.0; 192\\.168\\.2\\.1:47808 mask=255\\.255\\.255\\.0")

add_test(NAME bacnet_read_bdt_request_and_ack_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_read_bdt_request_and_ack_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "BVLC Read-Broadcast-Distribution-Table\n.*BVLC Read-Broadcast-Distribution-Table-Ack \\(2 entry/entries\\)")

# 40-43) Register-Foreign-Device (TTL) / Read-FDT / Read-FDT-Ack (TTL+Timeout) / Delete-FDT-Entry.
add_test(NAME bacnet_register_foreign_device_ttl_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_register_foreign_device_ttl_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "BVLC Register-Foreign-Device ttl=300s\n *note: registration-ttl=300s")

add_test(NAME bacnet_read_fdt_request_and_ack_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_read_fdt_request_and_ack_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "BVLC Read-Foreign-Device-Table\n.*BVLC Read-Foreign-Device-Table-Ack \\(1 entry/entries\\)\n *note: 1 table entry/entries: 192\\.168\\.1\\.50:47808 ttl=300 timeout=180")

add_test(NAME bacnet_delete_fdt_entry_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_delete_fdt_entry_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "BVLC Delete-Foreign-Device-Table-Entry\n *note: delete-entry=192\\.168\\.1\\.50:47808")

# 44) Forwarded-NPDU -- the originating device's own address surfaced distinctly from this
# packet's own UDP/IP source (the relaying BBMD).
add_test(NAME bacnet_forwarded_npdu_originating_address_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_forwarded_npdu_originating_address_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "BVLC Forwarded-NPDU Unconfirmed-Request who-Is\n *note: forwarded-from=192\\.168\\.5\\.20:47808")

# 45) Distribute-Broadcast-To-Network.
add_test(NAME bacnet_distribute_broadcast_to_network_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_distribute_broadcast_to_network_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "BVLC Distribute-Broadcast-To-Network Unconfirmed-Request who-Is\n")

# 46) Secure-BVLL -- opaque, encrypted/signed, named only with an explanatory note.
add_test(NAME bacnet_secure_bvll_opaque_named_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_secure_bvll_opaque_named_only PROPERTIES
  PASS_REGULAR_EXPRESSION "BVLC Secure-BVLL\n *note: Secure-BVLL payload is encrypted/signed -- not decodable without key material this decoder has no access to")

# 47) BVLC declared Length mismatched against bytes actually present -- tolerated with a note, not
# a rejection (mirrors GOOSE/SV/EtherCAT's own tolerant-declared-length handling).
add_test(NAME bacnet_declared_length_mismatch_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_declared_length_mismatch_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "who-Is\n *note: BVLC header's own declared Length \\(18\\) does not match the 8 byte\\(s\\) actually present in this UDP datagram")

# 48-50) Truncated BVLC header, wrong Type byte (0x82, BACnet/SC's own), and an undefined Function
# byte (0x0D) -- all three must NOT be misdetected as BACnet/IP, falling back to the generic "udp"
# report -- see bacnet.hpp's "structural detection gate" paragraph. Exactly three such fallbacks
# appear consecutively (packets #48-50); packet #53 (below) is a fourth, separate udp fallback.
add_test(NAME bacnet_malformed_bvlc_header_falls_back_to_udp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_malformed_bvlc_header_falls_back_to_udp PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 2 byte\\(s\\)[^\n]*\n.*\\[udp\\]  UDP payload of 8 byte\\(s\\)[^\n]*\n.*\\[udp\\]  UDP payload of 8 byte\\(s\\)")

# 51) NPDU truncated right after Version/Control -- BVLC/NPDU still decode, no APDU present.
add_test(NAME bacnet_npdu_with_no_apdu_bytes_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_npdu_with_no_apdu_bytes_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "NPDU \\(no APDU\\)\n *note: no APDU bytes present after the NPDU header")

# 52) APDU PDU type not one of the 8 the spec defines -- BVLC/NPDU decode fine, only the APDU
# itself is left unrecognized.
add_test(NAME bacnet_apdu_type_not_recognized_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_apdu_type_not_recognized_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "NPDU \\(APDU type not recognized\\)\n *note: APDU type 15 is not one of the 8 the spec defines \\(0-7\\)")

# 53) Ordinary UDP traffic on an unrelated port -- must not be misdetected regardless of port (the
# structural gate is Type+Function, not port).
add_test(NAME bacnet_unrelated_udp_traffic_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --format text)
set_tests_properties(bacnet_unrelated_udp_traffic_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "51000->51001\n")

add_test(NAME bacnet_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_bacnet.pcap" --stats)
set_tests_properties(bacnet_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +53[^\n]*\n[^\n]*\nprotocols:\n *bacnet +49\n *udp +4\nbacnet bvlc functions:\n *BVLC-Result +1\n.*bacnet apdu services:\n *i-Am +2\n")

# --------------------------------------------------------------------------
# Real-world BACnet/IP capture -- see tests/real_captures/bacnet/ATTRIBUTION.md for provenance: a
# 54-frame excerpt of mrhenrike/PCAPTrafficAnalysis's ICS-OT-Network-001.pcap, a ReadProperty
# polling session against trend-log objects 34-42 (total-record-count/record-count/
# last-notify-record, all plain Unsigned Integer values). automayt/ICS-pcap's own BACNET/
# directory (23 files) was checked first and found to be Git-LFS pointer stubs this environment
# cannot resolve -- see ATTRIBUTION.md for the full search record, including kargs.net's own
# capture archive being blocked by this session's network policy.
# --------------------------------------------------------------------------
add_test(NAME real_bacnet_ics_ot_network_001_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/bacnet/ICS-OT-Network-001-bacnet-excerpt.pcap" --format json)

add_test(NAME real_bacnet_stats_all_original_unicast_readproperty
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/bacnet/ICS-OT-Network-001-bacnet-excerpt.pcap" --stats)
set_tests_properties(real_bacnet_stats_all_original_unicast_readproperty PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +54[^\n]*\n[^\n]*\nprotocols:\n *bacnet +54\nbacnet bvlc functions:\n *Original-Unicast-NPDU +54\nbacnet apdu services:\n *readProperty +54")

add_test(NAME real_bacnet_first_request_response_pair_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/bacnet/ICS-OT-Network-001-bacnet-excerpt.pcap" --format text)
set_tests_properties(real_bacnet_first_request_response_pair_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Confirmed-Request invoke-id=52 readProperty \\[object=trend-log,34 \\+1 more\\]\n.*Complex-ACK invoke-id=52 readProperty \\[object=trend-log,34 \\+2 more\\]")

# Trend-log fill-state properties -- every ReadProperty-ACK's value decodes as a plain
# application-tagged Unsigned Integer (see ATTRIBUTION.md for the full property/value breakdown).
add_test(NAME real_bacnet_trend_log_properties_decoded_as_unsigned
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/bacnet/ICS-OT-Network-001-bacnet-excerpt.pcap")
set_tests_properties(real_bacnet_trend_log_properties_decoded_as_unsigned PROPERTIES
  PASS_REGULAR_EXPRESSION "\"object=trend-log,34\", \"property=total-record-count\", \"value=\\(Unsigned Integer\\) 347329\"")

# Every note in this real capture is the same ordinary Ethernet-padding-trim note (27 of the 54
# Confirmed-Request frames carry it, confirmed via `grep -c` while writing this fixture -- see
# ATTRIBUTION.md) -- no parse-error, no fallback-protocol, no unexpected note text anywhere else
# in the file. real_bacnet_stats_all_original_unicast_readproperty above already confirms all 54
# frames land as bacnet/readProperty with no fallback; this confirms the padding note's exact,
# expected text.
add_test(NAME real_bacnet_padding_note_text_as_expected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/bacnet/ICS-OT-Network-001-bacnet-excerpt.pcap" --format text)
set_tests_properties(real_bacnet_padding_note_text_as_expected PROPERTIES
  PASS_REGULAR_EXPRESSION "note: 1 trailing byte\\(s\\) after the IP header's declared total length were trimmed \\(almost always Ethernet minimum-frame-size padding, not real payload\\)")

# --------------------------------------------------------------------------
# Real-world S7comm/COTP captures -- see tests/real_captures/s7comm/ATTRIBUTION.md
# for provenance. 14 from github.com/automayt/ICS-pcap's S7/ directory (good
# additional real-world coverage of classic S7ANY item decoding and the
# S7comm-Plus detection stub -- none of them turned out to contain real 0xB2
# traffic, see ATTRIBUTION.md for why), plus one file
# (s7comm_1200sym_real_polling.pcap) with different provenance: a small slice
# manually extracted from a much larger (140MB) real capture containing over
# a million real 0xB2 items, all decoding with zero fallbacks -- almost
# certainly the SAME real session already behind this project's original
# single-shape 0xB2 validation, not an independent new one (see
# ATTRIBUTION.md), but confirming that shape holds at full-session volume
# rather than just the handful of items originally spot-checked.
# --------------------------------------------------------------------------
set(S7COMM_REAL_CAPTURES
  s7comm_varservice_read_db1dbd0
  s7comm_varservice_cyclicdata_1s
  s7comm_vat_mb100_mw200_md300_m400
  s7comm_download_db1_with_password_request
  s7comm_1200_uploading_ob1_tiav12
  s7comm_plus_1511_opc_request_all_types
  s7comm_plus_1511_db3_var1_hmi
  s7comm_1200_hmi
  s7comm_downloading_block_db1
  s7comm_program_blocklist_onlineview
  s7comm_reading_plc_status
  s7comm_reading_setting_plc_time
  s7comm_varservice_libnodavedemo_bench
  s7comm_varservice_libnodavedemo
  s7comm_1200sym_real_polling
)
foreach(capture ${S7COMM_REAL_CAPTURES})
  add_test(NAME real_s7comm_${capture}_does_not_crash
    COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/${capture}.pcap" --format json)
endforeach()

add_test(NAME real_s7comm_read_db1dbd0_item_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_varservice_read_db1dbd0.pcap" --format text)
set_tests_properties(real_s7comm_read_db1dbd0_item_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "item 0: DB1\\.DBB0")

# Real EOT-chaining evidence: this capture's PLC precedes almost every real Read Var response with
# a zero-byte EOT=0 "priming" COTP Data frame before the real EOT=1 frame -- see
# tests/real_captures/s7comm/ATTRIBUTION.md for how this shape was confirmed across every real
# S7comm capture checked for this project (content-free in all of them; a genuinely
# content-split real-world chain has yet to be seen -- see sample_s7comm_chaining.pcap for a
# synthetic one that does split real content). Decoder::reassemble_cotp_data_frame must
# transparently chain across it (0 buffered bytes + the real frame's own bytes = unchanged
# decoded content) rather than mishandling or crashing on it.
add_test(NAME real_s7comm_read_db1dbd0_eot_chaining_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_varservice_read_db1dbd0.pcap" --format text)
set_tests_properties(real_s7comm_read_db1dbd0_eot_chaining_note PROPERTIES
  PASS_REGULAR_EXPRESSION "reassembled a COTP/S7comm message from 24 user-data byte\\(s\\) chained across 2 complete TPKT/COTP frames")

# A capture named after S7-1500 HMI traffic that turns out to be S7comm-Plus,
# not classic S7comm -- regression guard that the S7comm-Plus detection stub
# fires correctly on real traffic, not just the one it was written against.
add_test(NAME real_s7comm_plus_detected_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format text)
set_tests_properties(real_s7comm_plus_detected_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "S7comm-Plus \\(TIA Portal S7-1200/1500 protocol\\) detected, not decoded")

# Real 0xB2 (1200SYM) traffic: structural decode must still succeed (no
# "unrecognized area1"/"multi-LID" fallback), matching what held across the
# full 1M+-item source file this slice was taken from (see ATTRIBUTION.md --
# likely the same real session behind the project's original 0xB2 finding,
# not an independent one, but now checked at full volume instead of a
# handful of spot-checked items).
add_test(NAME real_s7comm_1200sym_item_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_1200sym_real_polling.pcap" --format text)
set_tests_properties(real_s7comm_1200sym_item_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "item 0: M2\\.0 \\[EXPERIMENTAL 1200SYM \\(0xB2\\) decode, unverified -- reserved=0xff00 crc=0xea2db0d9"
  FAIL_REGULAR_EXPRESSION "unrecognized area1|multi-LID|byte\\(s\\) left after its CRC")

add_test(NAME real_s7comm_1200sym_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_1200sym_real_polling.pcap" --format text)
set_tests_properties(real_s7comm_1200sym_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "value 0: Success = 00")

# --------------------------------------------------------------------------
# Real-world Modbus/TCP captures -- see tests/real_captures/modbus/ATTRIBUTION.md.
# Until now Modbus decoding had no real-traffic regression fixture at all,
# only synthetic ones.
# --------------------------------------------------------------------------
set(MODBUS_REAL_CAPTURES
  modbus_read_holding_registers
  modbus_test_data_part1
  modbus_test_data_part2
)
foreach(capture ${MODBUS_REAL_CAPTURES})
  add_test(NAME real_modbus_${capture}_does_not_crash
    COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/modbus/${capture}.pcap" --format json)
endforeach()

add_test(NAME real_modbus_read_holding_registers_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/modbus/modbus_read_holding_registers.pcap" --format text)
set_tests_properties(real_modbus_read_holding_registers_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Read Holding Registers: request: read 1 holding register\\(s\\) starting at address 1")

# Real authoritative pairing evidence: this capture's request/response pairs share one TCP session,
# so Decoder::pair_modbus_transaction must pair the first real response back to its real request.
add_test(NAME real_modbus_read_holding_registers_authoritative_pairing
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/modbus/modbus_read_holding_registers.pcap" --format text)
set_tests_properties(real_modbus_read_holding_registers_authoritative_pairing PROPERTIES
  PASS_REGULAR_EXPRESSION "authoritative pairing: response to transaction id 209 \\(unit 1\\) -- matches the request seen in packet #1")

# Real traffic exercising a function code outside current scope must degrade
# to a "not decoded" note, not be misparsed.
add_test(NAME real_modbus_diagnostics_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/modbus/modbus_test_data_part1.pcap" --format text)
set_tests_properties(real_modbus_diagnostics_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Diagnostics: Diagnostics \\(not decoded in this groundwork release\\)")

add_test(NAME decode_s7comm_sample
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(decode_s7comm_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "Setup Communication")

add_test(NAME decode_s7comm_readvar_sample
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format json)
set_tests_properties(decode_s7comm_readvar_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "Read Var")

add_test(NAME decode_cotp_connection_request_sample
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(decode_cotp_connection_request_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "Connection Request \\(CR\\) calling-TSAP")

add_test(NAME s7comm_read_var_item_address
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(s7comm_read_var_item_address PROPERTIES
  PASS_REGULAR_EXPRESSION "DB10\\.DBW100")

add_test(NAME s7comm_read_var_returned_value
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(s7comm_read_var_returned_value PROPERTIES
  PASS_REGULAR_EXPRESSION "value 0: Success = 00 01 00 02 00 03 00 04 00 05")

add_test(NAME s7comm_write_var_item_address
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(s7comm_write_var_item_address PROPERTIES
  PASS_REGULAR_EXPRESSION "M0\\.0")

# Regression guard: a Write Var request's per-item "reserved" byte (always 0x00 on the
# wire) must never be rendered as if it were the return-code table's entry for 0x00
# ("Reserved") -- it isn't a return code at all on a request, and doing so masked the
# actual written value the first time this was implemented.
add_test(NAME s7comm_write_var_value_not_mislabeled
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(s7comm_write_var_value_not_mislabeled PROPERTIES
  PASS_REGULAR_EXPRESSION "value 0: 01"
  FAIL_REGULAR_EXPRESSION "Write Var.*Reserved")

add_test(NAME s7comm_area_codes_and_transport_sizes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_items.pcap" --format text)
set_tests_properties(s7comm_area_codes_and_transport_sizes PROPERTIES
  PASS_REGULAR_EXPRESSION "item 3: DB5\\.DBD20")

add_test(NAME s7comm_timer_area
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_items.pcap" --format text)
set_tests_properties(s7comm_timer_area PROPERTIES
  PASS_REGULAR_EXPRESSION "item 5: T5")

add_test(NAME s7comm_counter_area
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_items.pcap" --format text)
set_tests_properties(s7comm_counter_area PROPERTIES
  PASS_REGULAR_EXPRESSION "item 6: C3")

add_test(NAME s7comm_unsupported_syntax_id_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_items.pcap" --format text)
set_tests_properties(s7comm_unsupported_syntax_id_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "syntax id 0xb0.*not decoded")

add_test(NAME s7comm_1200sym_experimental_decode
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format text)
set_tests_properties(s7comm_1200sym_experimental_decode PROPERTIES
  PASS_REGULAR_EXPRESSION "item 4: M2\\.4 \\[EXPERIMENTAL 1200SYM")

add_test(NAME s7comm_1200sym_marked_in_summary
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format text)
set_tests_properties(s7comm_1200sym_marked_in_summary PROPERTIES
  PASS_REGULAR_EXPRESSION "M2\\.0 \\[EXPERIMENTAL\\]")

add_test(NAME s7comm_1200sym_marked_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format json)
set_tests_properties(s7comm_1200sym_marked_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"M2\\.0 \\[EXPERIMENTAL\\]\"")

# Fallback paths: shapes the experimental decode deliberately does not guess at.
add_test(NAME s7comm_1200sym_unrecognized_area1_falls_back
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format text)
set_tests_properties(s7comm_1200sym_unrecognized_area1_falls_back PROPERTIES
  PASS_REGULAR_EXPRESSION "item 5 is a 1200SYM \\(0xB2\\) item with an unrecognized area1 value")

add_test(NAME s7comm_1200sym_multi_lid_falls_back
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format text)
set_tests_properties(s7comm_1200sym_multi_lid_falls_back PROPERTIES
  PASS_REGULAR_EXPRESSION "item 6 is a 1200SYM \\(0xB2\\) item with 8 byte\\(s\\) left after its CRC")

add_test(NAME s7comm_item_tags_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format json)
set_tests_properties(s7comm_item_tags_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7comm_items\": \\[\"DB10\\.DBW100\"\\]")

# --------------------------------------------------------------------------
# Chaining a single S7comm message across multiple COMPLETE TPKT/COTP frames via the EOT bit
# (Decoder::reassemble_cotp_data_frame / cotp_reassembly_) -- a different, higher layer from
# General TCP stream reassembly above: every individual TPKT frame here is itself well-formed and
# complete, but the logical S7comm message inside only decodes correctly once several are chained
# together. tests/sample_s7comm_chaining.pcap, scenarios A-B.
# --------------------------------------------------------------------------

# A) The first (EOT=0) frame alone must show only "beginning...", never an s7comm decode; the
# second (EOT=1) frame must complete it and decode the CONCATENATED bytes correctly -- the split
# lands mid-byte inside a register value itself (see the fixture's own comment), so a wrong decode
# here would mean the reassembly corrupted content, not just failed to buffer.
add_test(NAME s7comm_chaining_first_frame_buffers
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_chaining.pcap" --format text)
set_tests_properties(s7comm_chaining_first_frame_buffers PROPERTIES
  PASS_REGULAR_EXPRESSION "#1  [^#]*\\[cotp\\]  beginning a COTP/S7comm message fragmented across multiple complete TPKT/COTP frames on this TCP flow \\(EOT=0\\): 21 user-data byte\\(s\\) buffered across 1 frame\\(s\\)")

add_test(NAME s7comm_chaining_completes_with_correct_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_chaining.pcap" --format text)
set_tests_properties(s7comm_chaining_completes_with_correct_values PROPERTIES
  PASS_REGULAR_EXPRESSION "Ack_Data: Read Var \\(1 value\\(s\\): 13 ec 13 ed 13 ee 13 ef 13 f0\\)[^#]*reassembled a COTP/S7comm message from 28 user-data byte\\(s\\) chained across 2 complete TPKT/COTP frames")

# B) A Disconnect Request mid-reassembly abandons the in-progress fragment with a note rather than
# silently dropping it or splicing the Disconnect frame's own (irrelevant) bytes in.
add_test(NAME s7comm_chaining_disconnect_abandons_reassembly
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_chaining.pcap" --format text)
set_tests_properties(s7comm_chaining_disconnect_abandons_reassembly PROPERTIES
  PASS_REGULAR_EXPRESSION "a Disconnect Request \\(DR\\) frame arrived on this TCP flow while a COTP/S7comm fragment reassembly was still in progress \\(21 byte\\(s\\) buffered across 1 frame\\(s\\)\\) -- the earlier, incomplete fragment is abandoned")

# Regression guard for a real false positive: non-Modbus traffic (here, bytes that also happen
# to satisfy DNP3's 0x05 0x64 start) whose first four bytes look like transaction_id + a valid
# protocol_id==0, and whose function-code byte is 0x00 -- reserved/never assigned in the Modbus
# spec. Found via a real capture (DNP3 traffic on port 20000 mislabeled as Modbus); must now fall
# through to DNP3 detection instead.
add_test(NAME modbus_function_code_zero_is_not_modbus
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_false_positive.pcap" --format text)
set_tests_properties(modbus_function_code_zero_is_not_modbus PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[dnp3\\]"
  FAIL_REGULAR_EXPRESSION "\\[modbus\\]")

# --------------------------------------------------------------------------
# Authoritative (MBAP transaction-ID + TCP-session, non-heuristic) Modbus request/response pairing
# (Decoder::pair_modbus_transaction / modbus_pending_), layered on top of -- never replacing --
# modbus.cpp's own payload-shape heuristic. sample_modbus.pcap already incidentally exercises the
# common read-family pairing case and one orphan response; sample_modbus_pairing.pcap covers the
# cases that need their own scenario -- see its own file comment for why.
# --------------------------------------------------------------------------

# A) Write Single Register: request and response share the IDENTICAL 4-byte shape per spec -- the
# heuristic alone cannot tell them apart (its own note says so), so this is the strongest
# real-world case for this feature. The response must still be authoritatively paired to packet #1.
add_test(NAME modbus_pairing_write_single_paired_despite_ambiguous_shape
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_pairing.pcap" --format text)
set_tests_properties(modbus_pairing_write_single_paired_despite_ambiguous_shape PROPERTIES
  PASS_REGULAR_EXPRESSION "authoritative pairing: response to transaction id 500 \\(unit 1\\) -- matches the request seen in packet #1")

# B) A reused transaction ID before its first request is ever answered must be noted, and the
# eventual response must pair to the SECOND (most recently outstanding) request, not the first.
add_test(NAME modbus_pairing_reused_transaction_id_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_pairing.pcap" --format text)
set_tests_properties(modbus_pairing_reused_transaction_id_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "transaction id 600 reused on this TCP flow before its previous outstanding request \\(packet #3\\) was matched with a response")

add_test(NAME modbus_pairing_reused_transaction_id_pairs_to_latest_request
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_pairing.pcap" --format text)
set_tests_properties(modbus_pairing_reused_transaction_id_pairs_to_latest_request PROPERTIES
  PASS_REGULAR_EXPRESSION "authoritative pairing: response to transaction id 600 \\(unit 1\\) -- matches the request seen in packet #4 \\(Read Holding Registers: request: read 5 holding register\\(s\\) starting at address 100\\)")

# C) An orphan response (its request never seen on this session) -- already exercised incidentally
# by sample_modbus.pcap's exception-response packet (transaction id 2, no matching request).
add_test(NAME modbus_pairing_orphan_response_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --format text)
set_tests_properties(modbus_pairing_orphan_response_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "no outstanding request found on this TCP session for transaction id 2")

add_test(NAME info_modbus_sample
  COMMAND conduitscope info --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap")
set_tests_properties(info_modbus_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "packets:")

add_test(NAME stats_mode
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --stats)
set_tests_properties(stats_mode PROPERTIES
  PASS_REGULAR_EXPRESSION "modbus function codes:")

add_test(NAME stats_mode_s7comm
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --stats)
set_tests_properties(stats_mode_s7comm PROPERTIES
  PASS_REGULAR_EXPRESSION "s7comm function codes:")

add_test(NAME padded_ack_no_phantom_payload
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_padded_ack.pcap" --format text)
set_tests_properties(padded_ack_no_phantom_payload PROPERTIES
  PASS_REGULAR_EXPRESSION "no payload"
  FAIL_REGULAR_EXPRESSION "TCP payload of")

add_test(NAME padded_ack_trim_note_present
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_padded_ack.pcap" --format text)
set_tests_properties(padded_ack_trim_note_present PROPERTIES
  PASS_REGULAR_EXPRESSION "were trimmed")

# ---------------------------------------------------------------------------------------------
# pcapng support (pcap_reader.cpp's is_pcapng_/next_pcapng()). Fixtures generated by
# tools/make_sample_pcap.py's build_pcapng_*() functions.
# ---------------------------------------------------------------------------------------------

add_test(NAME rejects_malformed_pcapng
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/pcapng_bad_byte_order.pcapng")
set_tests_properties(rejects_malformed_pcapng PROPERTIES
  PASS_REGULAR_EXPRESSION "Section Header Block.*unrecognized byte-order magic")

add_test(NAME pcapng_basic_decodes_same_as_classic_pcap
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcapng" --stats)
set_tests_properties(pcapng_basic_decodes_same_as_classic_pcap PROPERTIES
  PASS_REGULAR_EXPRESSION "modbus exception responses: 1")

add_test(NAME pcapng_info_reports_pcapng_section_version
  COMMAND conduitscope info --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcapng")
set_tests_properties(pcapng_info_reports_pcapng_section_version PROPERTIES
  PASS_REGULAR_EXPRESSION "pcap version:   1.0")

add_test(NAME pcapng_nanosecond_resolution_reported
  COMMAND conduitscope info --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pcapng_nanosecond.pcapng")
set_tests_properties(pcapng_nanosecond_resolution_reported PROPERTIES
  PASS_REGULAR_EXPRESSION "timestamps:     nanosecond resolution")

add_test(NAME pcapng_multi_interface_uses_each_packets_own_link_type
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pcapng_multi_interface.pcapng" --format text)
set_tests_properties(pcapng_multi_interface_uses_each_packets_own_link_type PROPERTIES
  # Packet 2 is on interface 1 (raw IP, no Ethernet framing). If per-packet link type
  # weren't actually applied here (e.g. if interface 1's raw IP bytes were misread as an
  # Ethernet frame, the way they'd be decoded under interface 0's link type instead), this
  # wouldn't decode as a clean Modbus request at all.
  PASS_REGULAR_EXPRESSION "read 4 holding register\\(s\\) starting at address 0")

add_test(NAME pcapng_simple_packet_block_decodes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pcapng_simple_packet_block.pcapng" --format text)
set_tests_properties(pcapng_simple_packet_block_decodes PROPERTIES
  PASS_REGULAR_EXPRESSION "Read Holding Registers")


# ---------------------------------------------------------------------------------------------
# Colorized text output (output.cpp's TextWriter color_ path; --color/--no-color in cli_main.cpp).
# CTest's COMMAND always runs with stdout piped (never a real terminal), so the "auto" default
# (absent both flags) is exercised here as "no color, same as always being piped/redirected" --
# --color is what forces color on so these tests can actually see the ANSI codes.
# ---------------------------------------------------------------------------------------------

add_test(NAME color_auto_is_off_when_not_a_terminal
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap")
set_tests_properties(color_auto_is_off_when_not_a_terminal PROPERTIES
  FAIL_REGULAR_EXPRESSION "\\[36m")

add_test(NAME color_forced_on_with_color_flag
  COMMAND conduitscope --color decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap")
set_tests_properties(color_forced_on_with_color_flag PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[36m\\[modbus\\]")

add_test(NAME color_modbus_exception_highlighted_red
  COMMAND conduitscope --color decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap")
set_tests_properties(color_modbus_exception_highlighted_red PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[1;31mRead Holding Registers: exception response")

add_test(NAME color_no_color_flag_forces_off
  COMMAND conduitscope --no-color decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap")
set_tests_properties(color_no_color_flag_forces_off PROPERTIES
  FAIL_REGULAR_EXPRESSION "\\[36m")

add_test(NAME color_and_no_color_are_mutually_exclusive
  COMMAND conduitscope --color --no-color decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap")
set_tests_properties(color_and_no_color_are_mutually_exclusive PROPERTIES
  PASS_REGULAR_EXPRESSION "excludes")


# ---------------------------------------------------------------------------------------------
# `policy validate` -- zone/conduit policy engine (policy.hpp/policy_engine.hpp). Fixtures live
# under tests/policies/ (hand-authored YAML-subset policy files; see each file's own header
# comment for what it's for) and tests/sample_policy_engine.pcap (synthetic, see
# tools/make_sample_pcap.py's build_policy_engine_sample).
# ---------------------------------------------------------------------------------------------

set(POLICY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/policies")

add_test(NAME policy_modbus_sample_compliant
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_modbus_sample_compliant PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"HMI polls PLC via Modbus\"")

add_test(NAME policy_dnp3_sample_compliant
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_dnp3_sample_compliant PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT")

add_test(NAME policy_s7comm_sample_compliant
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_s7comm_sample_compliant PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"Engineering station S7comm\"")

add_test(NAME policy_json_format
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --format json)
set_tests_properties(policy_json_format PROPERTIES
  PASS_REGULAR_EXPRESSION "\"compliant\": true[^}]*\"verdict\": \"allowed\"")

add_test(NAME policy_wrong_port_is_a_violation
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/wrong_port.yaml")
set_tests_properties(policy_wrong_port_is_a_violation PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: NON-COMPLIANT \\(1 violation\\(s\\), 0 unclassified flow\\(s\\)\\).*a conduit exists between zone 'hmi_zone' and zone 'plc_zone', but none permits modbus traffic on port 502")

add_test(NAME policy_no_conduit_for_zone_pair_is_a_violation
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/no_conduit_for_zone_pair.yaml")
set_tests_properties(policy_no_conduit_for_zone_pair_is_a_violation PROPERTIES
  PASS_REGULAR_EXPRESSION "no conduit permits any traffic from zone 'hmi_zone' to zone 'plc_zone'")

add_test(NAME policy_unclassified_endpoint_reported
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/unclassified_zone.yaml")
set_tests_properties(policy_unclassified_endpoint_reported PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: NON-COMPLIANT \\(0 violation\\(s\\), 1 unclassified flow\\(s\\)\\).*no declared zone contains 192.168.1.10")

add_test(NAME policy_bidirectional_conduit_matches_reverse_direction
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bidirectional.yaml")
set_tests_properties(policy_bidirectional_conduit_matches_reverse_direction PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"PLC pushes to HMI")

add_test(NAME policy_unexercised_conduits_listed
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_unexercised_conduits_listed PROPERTIES
  PASS_REGULAR_EXPRESSION "Conduits never exercised by this capture \\(2\\):.*HMI polls PLC via DNP3.*Engineering station S7comm")

# sample_policy_engine.pcap: client/server (initiator) determination and cotp->s7comm folding.
add_test(NAME policy_engine_syn_handshake_gives_correct_direction
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_policy_engine.pcap" --policy "${POLICY_DIR}/policy_engine_sample.yaml" --format json)
set_tests_properties(policy_engine_syn_handshake_gives_correct_direction PROPERTIES
  PASS_REGULAR_EXPRESSION "\"client_ip\": \"192.168.1.50\",[^}]*\"server_ip\": \"192.168.1.10\",[^}]*\"server_port\": 502")

add_test(NAME policy_engine_late_syn_overrides_port_guess
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_policy_engine.pcap" --policy "${POLICY_DIR}/policy_engine_sample.yaml" --format json)
set_tests_properties(policy_engine_late_syn_overrides_port_guess PROPERTIES
  PASS_REGULAR_EXPRESSION "\"client_ip\": \"192.168.1.50\",[^}]*\"server_ip\": \"192.168.1.10\",[^}]*\"server_port\": 55000")

add_test(NAME policy_engine_no_protocol_recognized_is_unclassified
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_policy_engine.pcap" --policy "${POLICY_DIR}/policy_engine_sample.yaml")
set_tests_properties(policy_engine_no_protocol_recognized_is_unclassified PROPERTIES
  PASS_REGULAR_EXPRESSION "no Modbus/DNP3/S7comm traffic was recognized on this flow \\(2 unrecognized/handshake packet\\(s\\) only\\)")

add_test(NAME policy_engine_cotp_only_session_counts_as_s7comm
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_policy_engine.pcap" --policy "${POLICY_DIR}/policy_engine_sample.yaml" --format json)
set_tests_properties(policy_engine_cotp_only_session_counts_as_s7comm PROPERTIES
  PASS_REGULAR_EXPRESSION "\"server_port\": 102,[^}]*\"client_zone\": \"hmi_zone\",[^}]*\"server_zone\": \"plc_zone\",[^}]*\"protocols\": \\[\"s7comm\"\\][^}]*\"verdict\": \"allowed\"")

# Policy file validation errors -- each tests/policies/bad_*.yaml fixture exercises one specific
# rejection (see that file's own header comment for exactly what it's testing).
add_test(NAME policy_error_missing_zones
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_missing_zones.yaml")
set_tests_properties(policy_error_missing_zones PROPERTIES
  PASS_REGULAR_EXPRESSION "missing required top-level 'zones' key")

add_test(NAME policy_error_bad_cidr
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_cidr.yaml")
set_tests_properties(policy_error_bad_cidr PROPERTIES
  PASS_REGULAR_EXPRESSION "is not a valid IPv4 address or CIDR block")

add_test(NAME policy_error_unknown_zone_reference
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_unknown_zone.yaml")
set_tests_properties(policy_error_unknown_zone_reference PROPERTIES
  PASS_REGULAR_EXPRESSION "'to' zone 'z2' is not declared in 'zones'")

add_test(NAME policy_error_overlapping_zones
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_overlap.yaml")
set_tests_properties(policy_error_overlapping_zones PROPERTIES
  PASS_REGULAR_EXPRESSION "overlap -- each address must belong to at most one zone")

add_test(NAME policy_error_bad_port
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_port.yaml")
set_tests_properties(policy_error_bad_port PROPERTIES
  PASS_REGULAR_EXPRESSION "is not a valid TCP port")

add_test(NAME policy_error_reserved_zone_name
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_reserved_zone_name.yaml")
set_tests_properties(policy_error_reserved_zone_name PROPERTIES
  PASS_REGULAR_EXPRESSION "'unclassified' is a reserved zone name")

add_test(NAME policy_error_duplicate_zone_name
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_duplicate_zone.yaml")
set_tests_properties(policy_error_duplicate_zone_name PROPERTIES
  PASS_REGULAR_EXPRESSION "duplicate key 'z1'")

add_test(NAME policy_error_duplicate_conduit_name
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_duplicate_conduit.yaml")
set_tests_properties(policy_error_duplicate_conduit_name PROPERTIES
  PASS_REGULAR_EXPRESSION "duplicate conduit name 'c1'")

add_test(NAME policy_error_empty_conduits
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_empty_conduits.yaml")
set_tests_properties(policy_error_empty_conduits PROPERTIES
  PASS_REGULAR_EXPRESSION "'conduits' must declare at least one conduit")

add_test(NAME policy_error_tab_indentation
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_tab_indent.yaml")
set_tests_properties(policy_error_tab_indentation PROPERTIES
  PASS_REGULAR_EXPRESSION "tab characters are not supported for indentation")

add_test(NAME policy_error_bad_indentation
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_indentation.yaml")
set_tests_properties(policy_error_bad_indentation PROPERTIES
  PASS_REGULAR_EXPRESSION "indentation does not match any enclosing block")

add_test(NAME policy_error_flow_mapping_unsupported
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_flow_mapping.yaml")
set_tests_properties(policy_error_flow_mapping_unsupported PROPERTIES
  PASS_REGULAR_EXPRESSION "flow mappings \\('\\{\\.\\.\\.\\}'\\) are not supported")

add_test(NAME policy_error_missing_policy_file
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${CMAKE_CURRENT_SOURCE_DIR}/tests/policies/does_not_exist.yaml")
set_tests_properties(policy_error_missing_policy_file PROPERTIES
  WILL_FAIL TRUE)

add_test(NAME policy_output_to_file
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --output "${CMAKE_CURRENT_BINARY_DIR}/policy_report.txt")
set_tests_properties(policy_output_to_file PROPERTIES
  FAIL_REGULAR_EXPRESSION "COMPLIANT")

# Regression tests for two real bugs found in code review before this feature was first committed
# (see each fixture's own header comment for the full story).
add_test(NAME policy_trailing_comma_in_flow_sequence
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/trailing_commas.yaml")
set_tests_properties(policy_trailing_comma_in_flow_sequence PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"trailing commas everywhere\"")

add_test(NAME policy_error_line_number_is_the_zones_own_line
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_overlap_after_description.yaml")
set_tests_properties(policy_error_line_number_is_the_zones_own_line PROPERTIES
  PASS_REGULAR_EXPRESSION "bad_overlap_after_description.yaml:11: zone 'z1' .* and zone 'z2' .* overlap")

# ---------------------------------------------------------------------------------------------
# Live capture (live_capture.hpp/cpp) -- an optional, build-time-detected libpcap (Linux) / Npcap
# (Windows) dependency; see CMakeLists.txt's CONDUITSCOPE_HAVE_PCAP detection above. The CLI
# surface (-i/--interface, --filter, --duration, --snaplen, --no-promiscuous, `interfaces`) exists
# unconditionally -- only the runtime behavior behind it depends on CONDUITSCOPE_HAVE_PCAP -- so
# argument-validation tests below run regardless. Tests that actually open an interface are gated
# on CONDUITSCOPE_HAVE_PCAP (nothing to open otherwise) and, since this project has no CI configured
# yet and has only been exercised in a Linux dev sandbox so far, further gated on UNIX and scoped to
# loopback ("lo"), which every Linux/macOS host has; a Windows loopback interface has a different,
# non-portable name (see docs/MANUAL.md's LIVE CAPTURE section), so the Windows path is currently
# validated only by the argument-parsing tests, same honesty-about-scope convention as this
# project's other platform-specific caveats (e.g. the S7comm-Plus/DNP3 real-capture notes above).
# ---------------------------------------------------------------------------------------------

add_test(NAME live_capture_requires_exactly_one_source_decode
  COMMAND conduitscope decode)
set_tests_properties(live_capture_requires_exactly_one_source_decode PROPERTIES
  PASS_REGULAR_EXPRESSION "needs exactly one of -r/--read.*or -i/--interface")

add_test(NAME live_capture_input_and_interface_are_mutually_exclusive_decode
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --interface lo)
set_tests_properties(live_capture_input_and_interface_are_mutually_exclusive_decode PROPERTIES
  WILL_FAIL TRUE)

add_test(NAME live_capture_requires_exactly_one_source_policy_validate
  COMMAND conduitscope policy validate --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(live_capture_requires_exactly_one_source_policy_validate PROPERTIES
  PASS_REGULAR_EXPRESSION "needs exactly one of -r/--read.*or -i/--interface")

add_test(NAME live_capture_input_and_interface_are_mutually_exclusive_policy_validate
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --interface lo --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(live_capture_input_and_interface_are_mutually_exclusive_policy_validate PROPERTIES
  WILL_FAIL TRUE)

add_test(NAME live_capture_version_reports_support
  COMMAND conduitscope version)
if(CONDUITSCOPE_HAVE_PCAP)
  set_tests_properties(live_capture_version_reports_support PROPERTIES
    PASS_REGULAR_EXPRESSION "live capture: libpcap/Npcap")
else()
  set_tests_properties(live_capture_version_reports_support PROPERTIES
    PASS_REGULAR_EXPRESSION "live capture: not built in")
endif()

if(NOT CONDUITSCOPE_HAVE_PCAP)
  # This build was configured with CONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF, or simply didn't find
  # libpcap/Npcap -- confirm the stub path (live_capture.cpp's #else branch) gives a clear,
  # actionable error rather than a crash or a silent no-op, for both entry points.
  add_test(NAME live_capture_unavailable_interfaces_command
    COMMAND conduitscope interfaces)
  set_tests_properties(live_capture_unavailable_interfaces_command PROPERTIES
    PASS_REGULAR_EXPRESSION "live capture is not available.*libpcap.*Npcap")

  add_test(NAME live_capture_unavailable_decode_interface
    COMMAND conduitscope decode --interface lo --duration 1)
  set_tests_properties(live_capture_unavailable_decode_interface PROPERTIES
    PASS_REGULAR_EXPRESSION "live capture is not available.*libpcap.*Npcap")
else()
  # This build actually found libpcap/Npcap. A bad/nonexistent interface name is portable (no real
  # interface needs to exist on either platform for this to fail the way it's supposed to), so it
  # runs regardless of OS; everything else here opens "lo" specifically, which only exists (under
  # that name) on Linux/macOS -- Windows' loopback interface has a different, non-portable name
  # (see docs/MANUAL.md's LIVE CAPTURE section) -- so those are further gated on UNIX. This project
  # has no CI configured yet and has only actually been run on Linux so far; the Windows path is
  # validated only by the argument-parsing and bad-interface-name tests until that changes.
  add_test(NAME live_capture_bad_interface_name_reports_clearly
    COMMAND conduitscope decode --interface this_interface_does_not_exist --duration 1)
  set_tests_properties(live_capture_bad_interface_name_reports_clearly PROPERTIES
    PASS_REGULAR_EXPRESSION "cannot (open|activate) .*this_interface_does_not_exist")

  if(UNIX)
    # None of these depend on any traffic actually existing on "lo" during the run (--duration
    # alone must be enough to stop cleanly), so they don't need a traffic generator and stay
    # fast/deterministic.
    add_test(NAME live_capture_interfaces_command_lists_loopback
      COMMAND conduitscope interfaces)
    set_tests_properties(live_capture_interfaces_command_lists_loopback PROPERTIES
      PASS_REGULAR_EXPRESSION "lo  \\[loopback\\]")

    add_test(NAME live_capture_invalid_filter_reports_clearly
      COMMAND conduitscope decode --interface lo --filter "this is not valid bpf syntax {{{" --duration 1)
    set_tests_properties(live_capture_invalid_filter_reports_clearly PROPERTIES
      PASS_REGULAR_EXPRESSION "invalid capture filter")

    add_test(NAME live_capture_duration_stops_cleanly_with_no_traffic
      COMMAND conduitscope decode --interface lo --duration 1 --format text)
    set_tests_properties(live_capture_duration_stops_cleanly_with_no_traffic PROPERTIES
      TIMEOUT 10
      FAIL_REGULAR_EXPRESSION "error:")

    add_test(NAME live_capture_policy_validate_duration_stops_cleanly
      COMMAND conduitscope policy validate --interface lo --duration 1 --policy "${POLICY_DIR}/compliant.yaml")
    set_tests_properties(live_capture_policy_validate_duration_stops_cleanly PROPERTIES
      TIMEOUT 10
      PASS_REGULAR_EXPRESSION "capture: live:lo")

    # Every test above deliberately relies on "lo" carrying NO traffic, for determinism -- which
    # means none of them prove --max-packets actually bounds a live capture, or that live capture
    # decodes something real rather than just opening/closing cleanly. This one does: it generates
    # one real loopback TCP handshake attempt concurrently with a --max-packets=2 capture. See the
    # script's own header comment for exactly how, and why a bug here would hang (TIMEOUT) rather
    # than silently pass.
    add_test(NAME live_capture_max_packets_stops_capture_early_with_real_traffic
      COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/live_capture_max_packets_smoke.sh" "$<TARGET_FILE:conduitscope>")
    set_tests_properties(live_capture_max_packets_stops_capture_early_with_real_traffic PROPERTIES
      TIMEOUT 20)
  endif()
endif()
