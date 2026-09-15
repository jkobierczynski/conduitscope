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
  src/modbus.cpp
  src/dnp3.cpp
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
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --format json)
set_tests_properties(decode_modbus_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "Read Holding Registers")

add_test(NAME decode_dnp3_sample
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(decode_dnp3_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "DNP3 data link frame")

add_test(NAME dnp3_no_user_data_stays_link_only
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_no_user_data_stays_link_only PROPERTIES
  PASS_REGULAR_EXPRESSION "user_data=0 byte\\(s\\)"
  FAIL_REGULAR_EXPRESSION "user_data=0 byte\\(s\\)\\; transport")

add_test(NAME dnp3_transport_and_read_class0_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_transport_and_read_class0_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "transport: FIR=1 FIN=1 SEQ=0 \\| application:.*function=Read \\(0x01\\) objects: \\[g60v1\\]")

# The response packet's logical payload is 23 bytes -- over the 16-byte data-link block size --
# so this is also the regression guard for the multi-block CRC reassembly logic: if it mis-skips
# a block CRC, the object headers below would decode to garbage or fail to decode at all.
add_test(NAME dnp3_response_multiblock_object_headers
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_response_multiblock_object_headers PROPERTIES
  PASS_REGULAR_EXPRESSION "object 0: g1v2 \\(Binary Input\\) qualifier=0x00 range=0-2 -- 3 point\\(s\\), 3 byte\\(s\\) of object data")

add_test(NAME dnp3_response_second_object_after_block_boundary
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_response_second_object_after_block_boundary PROPERTIES
  PASS_REGULAR_EXPRESSION "object 1: g30v1 \\(Analog Input\\) qualifier=0x00 range=0-0 -- 1 point\\(s\\), 5 byte\\(s\\) of object data")

add_test(NAME dnp3_response_iin_flags_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_response_iin_flags_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Response \\(0x81\\) IIN=0x0080 \\[DEVICE_RESTART\\]")

# Multi-data-link-frame fragment (transport FIN=0): application layer must be left undecoded,
# not guessed at from the arbitrary trailing bytes in this fixture.
add_test(NAME dnp3_multiframe_fragment_application_not_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_multiframe_fragment_application_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "transport: FIR=1 FIN=0 SEQ=0"
  FAIL_REGULAR_EXPRESSION "transport: FIR=1 FIN=0 SEQ=0 \\| application")

add_test(NAME dnp3_unsupported_prefix_code_falls_back
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_unsupported_prefix_code_falls_back PROPERTIES
  PASS_REGULAR_EXPRESSION "prefix code 0x04 \\(object-size-prefixed or reserved\\), which this groundwork release does not decode")

add_test(NAME dnp3_function_in_json
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_function_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_function\": \"Response\"")

add_test(NAME dnp3_objects_in_json
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_objects_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_objects\": \\[\"g1v2 \\(Binary Input\\)\", \"g30v1 \\(Analog Input\\)\"\\]")

# Point-value decoding: byte 0 of the g1v2 object data is 0x81 (ONLINE flag + STATE bit set) --
# must decode to value "1" with the ONLINE flag, not just the raw byte length.
add_test(NAME dnp3_binary_input_value_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_binary_input_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "idx=0: 1 \\[ONLINE\\]")

add_test(NAME dnp3_analog_input_value_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_analog_input_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g30v1.*idx=0: 0 \\[ONLINE\\]")

# CROB command decode: control byte 0x43 = trip/close Close(1), control code Latch On(3);
# on_time=1000ms, off_time=0ms, status=0 (Success). High security relevance -- this is literally
# how DNP3 issues output commands, so getting every field named correctly matters.
add_test(NAME dnp3_crob_value_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_crob_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "idx=7: code=Latch On tc=Close queue/clear=0x00 count=1 on_time=1000ms off_time=0ms status=Success")

add_test(NAME dnp3_values_in_json
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_values_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_values\": \\[\"g1v2 idx=0: 1 \\[ONLINE\\]\"")

# Two complete DNP3 data-link frames coalesced into one TCP payload (packet 7 of
# sample_dnp3.pcap): the first frame's own function/summary must still be the headline, and the
# second frame -- previously silently dropped, since try_parse_dnp3_link_layer only ever looked
# at the start of the payload -- must now be fully decoded and surfaced via a note, not lost.
add_test(NAME dnp3_coalesced_frames_first_summary_unaffected
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_coalesced_frames_first_summary_unaffected PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Read \\(0x01\\) objects: \\[g60v1\\]")

add_test(NAME dnp3_coalesced_second_frame_noted
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_coalesced_second_frame_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "additional DNP3 data link frame 2 found in the same TCP payload at byte offset 18")

add_test(NAME dnp3_coalesced_second_frame_objects_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_coalesced_second_frame_objects_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g12v1 \\(Binary Output Command \\(CROB\\)\\).*idx=7: code=Latch On")

add_test(NAME dnp3_coalesced_frames_merged_in_json
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
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
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_start_frame_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "beginning a DNP3 fragment that spans multiple data-link frames \\(FIR=1, FIN=0, SEQ=5\\)"
  FAIL_REGULAR_EXPRESSION "transport: FIR=1 FIN=0 SEQ=5 \\| application")

# The FIN=1 completing frame (packet 9, a separate pcap packet from packet 8) must decode the
# full, concatenated application layer -- same CROB command as the single-frame packet 6, but
# reconstructed from two frames delivered a packet apart.
add_test(NAME dnp3_reassembly_completes_across_packets
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_completes_across_packets PROPERTIES
  PASS_REGULAR_EXPRESSION "completed a 2-data-link-frame DNP3 fragment reassembled across separate TCP segments \\(18 application-layer byte\\(s\\) total\\)")

add_test(NAME dnp3_reassembly_completed_object_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_completed_object_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Direct Operate \\(0x05\\) objects: \\[g12v1\\].*idx=7: code=Latch On tc=Close")

add_test(NAME dnp3_reassembly_completed_function_in_json
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_reassembly_completed_function_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 9,[^}]*\"dnp3_function\": \"Direct Operate\"")

# packet 5 (FIR=1,FIN=1, same TCP flow as packet 4's never-completed start) must abandon packet
# 4's stale in-progress reassembly rather than silently merging into it.
add_test(NAME dnp3_reassembly_abandoned_by_new_complete_fragment
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_abandoned_by_new_complete_fragment PROPERTIES
  PASS_REGULAR_EXPRESSION "a complete single-frame DNP3 fragment \\(FIR=1, FIN=1\\) arrived on this TCP flow while a previous multi-frame fragment reassembly was still in progress")

# packet 10: a FIR=0 continuation with no reassembly in progress on its flow at all (orphan) --
# must be left transport-only, with an explanatory note, never guessed at.
add_test(NAME dnp3_reassembly_orphan_continuation_noted
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_orphan_continuation_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "continuation DNP3 data-link frame \\(FIR=0, SEQ=1\\) with no fragment reassembly in progress on this TCP flow")

# packets 11-12: a sequence-number mismatch must discard the in-progress reassembly rather than
# concatenating bytes out of order.
add_test(NAME dnp3_reassembly_sequence_mismatch_discarded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_reassembly_sequence_mismatch_discarded PROPERTIES
  PASS_REGULAR_EXPRESSION "continuation DNP3 data-link frame's sequence number \\(35\\) does not follow the previous frame's \\(expected 11\\)")

add_test(NAME stats_mode_dnp3
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --stats)
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
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
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
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_modbus_completes PROPERTIES
  PASS_REGULAR_EXPRESSION "response: 20 data byte\\(s\\) = 00 00 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00 08 00 09[^#]*reassembled a Modbus/TCP PDU/frame from 29 byte\\(s\\) spanning 2 TCP segments")

# B) A complete single-data-link-frame DNP3 fragment split mid-*header* across two TCP segments.
add_test(NAME tcp_reassembly_dnp3_link_layer_completes
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_dnp3_link_layer_completes PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Read \\(0x01\\) objects: \\[g60v1\\][^#]*reassembled a DNP3 data-link PDU/frame from 18 byte\\(s\\) spanning 2 TCP segments")

# C) A TPKT/S7comm Setup Communication request split across two TCP segments.
add_test(NAME tcp_reassembly_tpkt_s7comm_completes
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_tpkt_s7comm_completes PROPERTIES
  PASS_REGULAR_EXPRESSION "Setup Communication \\(negotiated PDU length=240[^#]*reassembled a TPKT/COTP PDU/frame from 25 byte\\(s\\) spanning 2 TCP segments")

# D) A TCP sequence gap abandons the in-progress reassembly, and a later, ordinary request on the
# same flow still decodes normally afterward (the abandoned state doesn't wedge the flow).
add_test(NAME tcp_reassembly_gap_abandons_reassembly
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_gap_abandons_reassembly PROPERTIES
  PASS_REGULAR_EXPRESSION "TCP sequence gap on this flow \\(expected seq 30009, got 30509, 500 byte\\(s\\) apparently missing\\) -- abandoning an in-progress 9-byte PDU/frame reassembly")

add_test(NAME tcp_reassembly_flow_recovers_after_gap
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_flow_recovers_after_gap PROPERTIES
  PASS_REGULAR_EXPRESSION "request: read 10 holding register\\(s\\) starting at address 0")

# E) A fully-duplicate retransmission mid-reassembly is ignored, not misapplied; the real
# completing segment afterward still finishes the PDU correctly.
add_test(NAME tcp_reassembly_duplicate_retransmit_ignored
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_duplicate_retransmit_ignored PROPERTIES
  PASS_REGULAR_EXPRESSION "retransmitted/duplicate TCP segment 502->51604 \\(fully overlaps bytes already buffered for an in-progress 20-byte PDU/frame reassembly")

add_test(NAME tcp_reassembly_completes_despite_duplicate
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_completes_despite_duplicate PROPERTIES
  PASS_REGULAR_EXPRESSION "response: 20 data byte\\(s\\) = 00 00 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00 08 00 09[^#]*reassembled a Modbus/TCP PDU/frame from 29 byte\\(s\\) spanning 3 TCP segments")

# F) A partial-overlap retransmission (repeats a few already-buffered bytes, then extends past
# them with new ones) is trimmed to just its new bytes, not misaligned or duplicated.
add_test(NAME tcp_reassembly_partial_overlap_trimmed
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
set_tests_properties(tcp_reassembly_partial_overlap_trimmed PROPERTIES
  PASS_REGULAR_EXPRESSION "TCP segment on this flow overlaps 3 already-buffered byte\\(s\\) \\(likely a retransmission\\) -- trimmed and only the new byte\\(s\\) appended")

add_test(NAME tcp_reassembly_partial_overlap_completes_correctly
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_tcp_reassembly.pcap" --format text)
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
    COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/${capture}.pcap" --format json)
endforeach()

add_test(NAME real_dnp3_read_class1_poll_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_read.pcap" --format text)
set_tests_properties(real_dnp3_read_class1_poll_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Read \\(0x01\\) objects: \\[g60v2\\]")

# Real Select/Operate CROB sequence -- confirms the field-by-field CROB decode
# (control code, trip/close, queue/clear, on/off time, status) against an
# independent DNP3 master's actual wire encoding, not just the synthetic
# fixture's one hand-constructed control byte.
add_test(NAME real_dnp3_select_operate_crob_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_select_operate.pcap" --format text)
set_tests_properties(real_dnp3_select_operate_crob_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "idx=1: code=Latch On tc=NUL queue/clear=0x00 count=1 on_time=100ms off_time=100ms status=Success")

# Same CROB object, but a real operate attempt that the outstation rejected --
# confirms the IEEE 1815 control-status-code table isn't only decoding whichever
# single status value the synthetic fixture happens to use.
add_test(NAME real_dnp3_test_data_part2_crob_status_success
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part2.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part2_crob_status_success PROPERTIES
  PASS_REGULAR_EXPRESSION "status=Success")

add_test(NAME real_dnp3_test_data_part2_crob_status_not_supported
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part2.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part2_crob_status_not_supported PROPERTIES
  PASS_REGULAR_EXPRESSION "status=Not Supported")

# Real polling session: Binary Input (bit-packed), Binary Output (byte-per-point
# with flags), and Internal Indications objects all decoded from real traffic.
add_test(NAME real_dnp3_test_data_part1_binary_input_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part1.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part1_binary_input_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g1v1 \\(Binary Input\\).*idx=0: 0, idx=1: 1, idx=2: 0")

add_test(NAME real_dnp3_test_data_part1_binary_output_flags_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part1.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part1_binary_output_flags_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g10v2 \\(Binary Output\\).*idx=0: 0 \\[ONLINE\\]")

add_test(NAME real_dnp3_test_data_part1_internal_indications_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_test_data_part1.pcap" --format text)
set_tests_properties(real_dnp3_test_data_part1_internal_indications_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g80v1 \\(Internal Indications\\).*idx=7: 0")

# Absolute timestamp (group 50 var 1) from a real Write request, not the
# synthetic fixture.
add_test(NAME real_dnp3_write_timestamp_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_write.pcap" --format text)
set_tests_properties(real_dnp3_write_timestamp_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "g50v1 \\(Time and Date\\).*idx=0: 1156521360890ms-since-epoch")

# Deliberately corrupted/fuzzed capture: must degrade gracefully (a note
# explaining why parsing stopped) rather than silently fabricate a value for
# bytes that don't actually decode to anything meaningful.
add_test(NAME real_dnp3_malformed_bails_out_with_a_note
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_malformed.pcap" --format text)
set_tests_properties(real_dnp3_malformed_bails_out_with_a_note PROPERTIES
  PASS_REGULAR_EXPRESSION "is not in the known point-format table -- stopping object parsing")

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
    COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/${capture}.pcap" --format json)
endforeach()

add_test(NAME real_s7comm_read_db1dbd0_item_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_varservice_read_db1dbd0.pcap" --format text)
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
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_varservice_read_db1dbd0.pcap" --format text)
set_tests_properties(real_s7comm_read_db1dbd0_eot_chaining_note PROPERTIES
  PASS_REGULAR_EXPRESSION "reassembled a COTP/S7comm message from 24 user-data byte\\(s\\) chained across 2 complete TPKT/COTP frames")

# A capture named after S7-1500 HMI traffic that turns out to be S7comm-Plus,
# not classic S7comm -- regression guard that the S7comm-Plus detection stub
# fires correctly on real traffic, not just the one it was written against.
add_test(NAME real_s7comm_plus_detected_not_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format text)
set_tests_properties(real_s7comm_plus_detected_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "S7comm-Plus \\(TIA Portal S7-1200/1500 protocol\\) detected, not decoded")

# Real 0xB2 (1200SYM) traffic: structural decode must still succeed (no
# "unrecognized area1"/"multi-LID" fallback), matching what held across the
# full 1M+-item source file this slice was taken from (see ATTRIBUTION.md --
# likely the same real session behind the project's original 0xB2 finding,
# not an independent one, but now checked at full volume instead of a
# handful of spot-checked items).
add_test(NAME real_s7comm_1200sym_item_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_1200sym_real_polling.pcap" --format text)
set_tests_properties(real_s7comm_1200sym_item_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "item 0: M2\\.0 \\[EXPERIMENTAL 1200SYM \\(0xB2\\) decode, unverified -- reserved=0xff00 crc=0xea2db0d9"
  FAIL_REGULAR_EXPRESSION "unrecognized area1|multi-LID|byte\\(s\\) left after its CRC")

add_test(NAME real_s7comm_1200sym_response_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_1200sym_real_polling.pcap" --format text)
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
    COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/modbus/${capture}.pcap" --format json)
endforeach()

add_test(NAME real_modbus_read_holding_registers_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/modbus/modbus_read_holding_registers.pcap" --format text)
set_tests_properties(real_modbus_read_holding_registers_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Read Holding Registers: request: read 1 holding register\\(s\\) starting at address 1")

# Real authoritative pairing evidence: this capture's request/response pairs share one TCP session,
# so Decoder::pair_modbus_transaction must pair the first real response back to its real request.
add_test(NAME real_modbus_read_holding_registers_authoritative_pairing
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/modbus/modbus_read_holding_registers.pcap" --format text)
set_tests_properties(real_modbus_read_holding_registers_authoritative_pairing PROPERTIES
  PASS_REGULAR_EXPRESSION "authoritative pairing: response to transaction id 209 \\(unit 1\\) -- matches the request seen in packet #1")

# Real traffic exercising a function code outside current scope must degrade
# to a "not decoded" note, not be misparsed.
add_test(NAME real_modbus_diagnostics_not_decoded
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/modbus/modbus_test_data_part1.pcap" --format text)
set_tests_properties(real_modbus_diagnostics_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Diagnostics: Diagnostics \\(not decoded in this groundwork release\\)")

add_test(NAME decode_s7comm_sample
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(decode_s7comm_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "Setup Communication")

add_test(NAME decode_s7comm_readvar_sample
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format json)
set_tests_properties(decode_s7comm_readvar_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "Read Var")

add_test(NAME decode_cotp_connection_request_sample
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(decode_cotp_connection_request_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "Connection Request \\(CR\\) calling-TSAP")

add_test(NAME s7comm_read_var_item_address
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(s7comm_read_var_item_address PROPERTIES
  PASS_REGULAR_EXPRESSION "DB10\\.DBW100")

add_test(NAME s7comm_read_var_returned_value
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(s7comm_read_var_returned_value PROPERTIES
  PASS_REGULAR_EXPRESSION "value 0: Success = 00 01 00 02 00 03 00 04 00 05")

add_test(NAME s7comm_write_var_item_address
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(s7comm_write_var_item_address PROPERTIES
  PASS_REGULAR_EXPRESSION "M0\\.0")

# Regression guard: a Write Var request's per-item "reserved" byte (always 0x00 on the
# wire) must never be rendered as if it were the return-code table's entry for 0x00
# ("Reserved") -- it isn't a return code at all on a request, and doing so masked the
# actual written value the first time this was implemented.
add_test(NAME s7comm_write_var_value_not_mislabeled
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format text)
set_tests_properties(s7comm_write_var_value_not_mislabeled PROPERTIES
  PASS_REGULAR_EXPRESSION "value 0: 01"
  FAIL_REGULAR_EXPRESSION "Write Var.*Reserved")

add_test(NAME s7comm_area_codes_and_transport_sizes
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_items.pcap" --format text)
set_tests_properties(s7comm_area_codes_and_transport_sizes PROPERTIES
  PASS_REGULAR_EXPRESSION "item 3: DB5\\.DBD20")

add_test(NAME s7comm_timer_area
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_items.pcap" --format text)
set_tests_properties(s7comm_timer_area PROPERTIES
  PASS_REGULAR_EXPRESSION "item 5: T5")

add_test(NAME s7comm_counter_area
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_items.pcap" --format text)
set_tests_properties(s7comm_counter_area PROPERTIES
  PASS_REGULAR_EXPRESSION "item 6: C3")

add_test(NAME s7comm_unsupported_syntax_id_noted
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_items.pcap" --format text)
set_tests_properties(s7comm_unsupported_syntax_id_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "syntax id 0xb0.*not decoded")

add_test(NAME s7comm_1200sym_experimental_decode
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format text)
set_tests_properties(s7comm_1200sym_experimental_decode PROPERTIES
  PASS_REGULAR_EXPRESSION "item 4: M2\\.4 \\[EXPERIMENTAL 1200SYM")

add_test(NAME s7comm_1200sym_marked_in_summary
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format text)
set_tests_properties(s7comm_1200sym_marked_in_summary PROPERTIES
  PASS_REGULAR_EXPRESSION "M2\\.0 \\[EXPERIMENTAL\\]")

add_test(NAME s7comm_1200sym_marked_in_json
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format json)
set_tests_properties(s7comm_1200sym_marked_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"M2\\.0 \\[EXPERIMENTAL\\]\"")

# Fallback paths: shapes the experimental decode deliberately does not guess at.
add_test(NAME s7comm_1200sym_unrecognized_area1_falls_back
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format text)
set_tests_properties(s7comm_1200sym_unrecognized_area1_falls_back PROPERTIES
  PASS_REGULAR_EXPRESSION "item 5 is a 1200SYM \\(0xB2\\) item with an unrecognized area1 value")

add_test(NAME s7comm_1200sym_multi_lid_falls_back
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_1200sym.pcap" --format text)
set_tests_properties(s7comm_1200sym_multi_lid_falls_back PROPERTIES
  PASS_REGULAR_EXPRESSION "item 6 is a 1200SYM \\(0xB2\\) item with 8 byte\\(s\\) left after its CRC")

add_test(NAME s7comm_item_tags_in_json
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --format json)
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
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_chaining.pcap" --format text)
set_tests_properties(s7comm_chaining_first_frame_buffers PROPERTIES
  PASS_REGULAR_EXPRESSION "#1  [^#]*\\[cotp\\]  beginning a COTP/S7comm message fragmented across multiple complete TPKT/COTP frames on this TCP flow \\(EOT=0\\): 21 user-data byte\\(s\\) buffered across 1 frame\\(s\\)")

add_test(NAME s7comm_chaining_completes_with_correct_values
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_chaining.pcap" --format text)
set_tests_properties(s7comm_chaining_completes_with_correct_values PROPERTIES
  PASS_REGULAR_EXPRESSION "Ack_Data: Read Var \\(1 value\\(s\\): 13 ec 13 ed 13 ee 13 ef 13 f0\\)[^#]*reassembled a COTP/S7comm message from 28 user-data byte\\(s\\) chained across 2 complete TPKT/COTP frames")

# B) A Disconnect Request mid-reassembly abandons the in-progress fragment with a note rather than
# silently dropping it or splicing the Disconnect frame's own (irrelevant) bytes in.
add_test(NAME s7comm_chaining_disconnect_abandons_reassembly
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_chaining.pcap" --format text)
set_tests_properties(s7comm_chaining_disconnect_abandons_reassembly PROPERTIES
  PASS_REGULAR_EXPRESSION "a Disconnect Request \\(DR\\) frame arrived on this TCP flow while a COTP/S7comm fragment reassembly was still in progress \\(21 byte\\(s\\) buffered across 1 frame\\(s\\)\\) -- the earlier, incomplete fragment is abandoned")

# Regression guard for a real false positive: non-Modbus traffic (here, bytes that also happen
# to satisfy DNP3's 0x05 0x64 start) whose first four bytes look like transaction_id + a valid
# protocol_id==0, and whose function-code byte is 0x00 -- reserved/never assigned in the Modbus
# spec. Found via a real capture (DNP3 traffic on port 20000 mislabeled as Modbus); must now fall
# through to DNP3 detection instead.
add_test(NAME modbus_function_code_zero_is_not_modbus
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_false_positive.pcap" --format text)
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
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_pairing.pcap" --format text)
set_tests_properties(modbus_pairing_write_single_paired_despite_ambiguous_shape PROPERTIES
  PASS_REGULAR_EXPRESSION "authoritative pairing: response to transaction id 500 \\(unit 1\\) -- matches the request seen in packet #1")

# B) A reused transaction ID before its first request is ever answered must be noted, and the
# eventual response must pair to the SECOND (most recently outstanding) request, not the first.
add_test(NAME modbus_pairing_reused_transaction_id_noted
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_pairing.pcap" --format text)
set_tests_properties(modbus_pairing_reused_transaction_id_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "transaction id 600 reused on this TCP flow before its previous outstanding request \\(packet #3\\) was matched with a response")

add_test(NAME modbus_pairing_reused_transaction_id_pairs_to_latest_request
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_pairing.pcap" --format text)
set_tests_properties(modbus_pairing_reused_transaction_id_pairs_to_latest_request PROPERTIES
  PASS_REGULAR_EXPRESSION "authoritative pairing: response to transaction id 600 \\(unit 1\\) -- matches the request seen in packet #4 \\(Read Holding Registers: request: read 5 holding register\\(s\\) starting at address 100\\)")

# C) An orphan response (its request never seen on this session) -- already exercised incidentally
# by sample_modbus.pcap's exception-response packet (transaction id 2, no matching request).
add_test(NAME modbus_pairing_orphan_response_noted
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --format text)
set_tests_properties(modbus_pairing_orphan_response_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "no outstanding request found on this TCP session for transaction id 2")

add_test(NAME info_modbus_sample
  COMMAND conduitscope info --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap")
set_tests_properties(info_modbus_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "packets:")

add_test(NAME stats_mode
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --stats)
set_tests_properties(stats_mode PROPERTIES
  PASS_REGULAR_EXPRESSION "modbus function codes:")

add_test(NAME stats_mode_s7comm
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --stats)
set_tests_properties(stats_mode_s7comm PROPERTIES
  PASS_REGULAR_EXPRESSION "s7comm function codes:")

add_test(NAME padded_ack_no_phantom_payload
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_padded_ack.pcap" --format text)
set_tests_properties(padded_ack_no_phantom_payload PROPERTIES
  PASS_REGULAR_EXPRESSION "no payload"
  FAIL_REGULAR_EXPRESSION "TCP payload of")

add_test(NAME padded_ack_trim_note_present
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_padded_ack.pcap" --format text)
set_tests_properties(padded_ack_trim_note_present PROPERTIES
  PASS_REGULAR_EXPRESSION "were trimmed")

add_test(NAME rejects_pcapng
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/not_a_pcap.pcapng")
set_tests_properties(rejects_pcapng PROPERTIES
  PASS_REGULAR_EXPRESSION "pcapng")


# ---------------------------------------------------------------------------------------------
# `policy validate` -- zone/conduit policy engine (policy.hpp/policy_engine.hpp). Fixtures live
# under tests/policies/ (hand-authored YAML-subset policy files; see each file's own header
# comment for what it's for) and tests/sample_policy_engine.pcap (synthetic, see
# tools/make_sample_pcap.py's build_policy_engine_sample).
# ---------------------------------------------------------------------------------------------

set(POLICY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/policies")

add_test(NAME policy_modbus_sample_compliant
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_modbus_sample_compliant PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"HMI polls PLC via Modbus\"")

add_test(NAME policy_dnp3_sample_compliant
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_dnp3_sample_compliant PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT")

add_test(NAME policy_s7comm_sample_compliant
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_s7comm_sample_compliant PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"Engineering station S7comm\"")

add_test(NAME policy_json_format
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --format json)
set_tests_properties(policy_json_format PROPERTIES
  PASS_REGULAR_EXPRESSION "\"compliant\": true[^}]*\"verdict\": \"allowed\"")

add_test(NAME policy_wrong_port_is_a_violation
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/wrong_port.yaml")
set_tests_properties(policy_wrong_port_is_a_violation PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: NON-COMPLIANT \\(1 violation\\(s\\), 0 unclassified flow\\(s\\)\\).*a conduit exists between zone 'hmi_zone' and zone 'plc_zone', but none permits modbus traffic on port 502")

add_test(NAME policy_no_conduit_for_zone_pair_is_a_violation
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/no_conduit_for_zone_pair.yaml")
set_tests_properties(policy_no_conduit_for_zone_pair_is_a_violation PROPERTIES
  PASS_REGULAR_EXPRESSION "no conduit permits any traffic from zone 'hmi_zone' to zone 'plc_zone'")

add_test(NAME policy_unclassified_endpoint_reported
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/unclassified_zone.yaml")
set_tests_properties(policy_unclassified_endpoint_reported PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: NON-COMPLIANT \\(0 violation\\(s\\), 1 unclassified flow\\(s\\)\\).*no declared zone contains 192.168.1.10")

add_test(NAME policy_bidirectional_conduit_matches_reverse_direction
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bidirectional.yaml")
set_tests_properties(policy_bidirectional_conduit_matches_reverse_direction PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"PLC pushes to HMI")

add_test(NAME policy_unexercised_conduits_listed
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_unexercised_conduits_listed PROPERTIES
  PASS_REGULAR_EXPRESSION "Conduits never exercised by this capture \\(2\\):.*HMI polls PLC via DNP3.*Engineering station S7comm")

# sample_policy_engine.pcap: client/server (initiator) determination and cotp->s7comm folding.
add_test(NAME policy_engine_syn_handshake_gives_correct_direction
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_policy_engine.pcap" --policy "${POLICY_DIR}/policy_engine_sample.yaml" --format json)
set_tests_properties(policy_engine_syn_handshake_gives_correct_direction PROPERTIES
  PASS_REGULAR_EXPRESSION "\"client_ip\": \"192.168.1.50\",[^}]*\"server_ip\": \"192.168.1.10\",[^}]*\"server_port\": 502")

add_test(NAME policy_engine_late_syn_overrides_port_guess
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_policy_engine.pcap" --policy "${POLICY_DIR}/policy_engine_sample.yaml" --format json)
set_tests_properties(policy_engine_late_syn_overrides_port_guess PROPERTIES
  PASS_REGULAR_EXPRESSION "\"client_ip\": \"192.168.1.50\",[^}]*\"server_ip\": \"192.168.1.10\",[^}]*\"server_port\": 55000")

add_test(NAME policy_engine_no_protocol_recognized_is_unclassified
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_policy_engine.pcap" --policy "${POLICY_DIR}/policy_engine_sample.yaml")
set_tests_properties(policy_engine_no_protocol_recognized_is_unclassified PROPERTIES
  PASS_REGULAR_EXPRESSION "no Modbus/DNP3/S7comm traffic was recognized on this flow \\(2 unrecognized/handshake packet\\(s\\) only\\)")

add_test(NAME policy_engine_cotp_only_session_counts_as_s7comm
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_policy_engine.pcap" --policy "${POLICY_DIR}/policy_engine_sample.yaml" --format json)
set_tests_properties(policy_engine_cotp_only_session_counts_as_s7comm PROPERTIES
  PASS_REGULAR_EXPRESSION "\"server_port\": 102,[^}]*\"client_zone\": \"hmi_zone\",[^}]*\"server_zone\": \"plc_zone\",[^}]*\"protocols\": \\[\"s7comm\"\\][^}]*\"verdict\": \"allowed\"")

# Policy file validation errors -- each tests/policies/bad_*.yaml fixture exercises one specific
# rejection (see that file's own header comment for exactly what it's testing).
add_test(NAME policy_error_missing_zones
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_missing_zones.yaml")
set_tests_properties(policy_error_missing_zones PROPERTIES
  PASS_REGULAR_EXPRESSION "missing required top-level 'zones' key")

add_test(NAME policy_error_bad_cidr
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_cidr.yaml")
set_tests_properties(policy_error_bad_cidr PROPERTIES
  PASS_REGULAR_EXPRESSION "is not a valid IPv4 address or CIDR block")

add_test(NAME policy_error_unknown_zone_reference
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_unknown_zone.yaml")
set_tests_properties(policy_error_unknown_zone_reference PROPERTIES
  PASS_REGULAR_EXPRESSION "'to' zone 'z2' is not declared in 'zones'")

add_test(NAME policy_error_overlapping_zones
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_overlap.yaml")
set_tests_properties(policy_error_overlapping_zones PROPERTIES
  PASS_REGULAR_EXPRESSION "overlap -- each address must belong to at most one zone")

add_test(NAME policy_error_bad_port
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_port.yaml")
set_tests_properties(policy_error_bad_port PROPERTIES
  PASS_REGULAR_EXPRESSION "is not a valid TCP port")

add_test(NAME policy_error_reserved_zone_name
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_reserved_zone_name.yaml")
set_tests_properties(policy_error_reserved_zone_name PROPERTIES
  PASS_REGULAR_EXPRESSION "'unclassified' is a reserved zone name")

add_test(NAME policy_error_duplicate_zone_name
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_duplicate_zone.yaml")
set_tests_properties(policy_error_duplicate_zone_name PROPERTIES
  PASS_REGULAR_EXPRESSION "duplicate key 'z1'")

add_test(NAME policy_error_duplicate_conduit_name
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_duplicate_conduit.yaml")
set_tests_properties(policy_error_duplicate_conduit_name PROPERTIES
  PASS_REGULAR_EXPRESSION "duplicate conduit name 'c1'")

add_test(NAME policy_error_empty_conduits
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_empty_conduits.yaml")
set_tests_properties(policy_error_empty_conduits PROPERTIES
  PASS_REGULAR_EXPRESSION "'conduits' must declare at least one conduit")

add_test(NAME policy_error_tab_indentation
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_tab_indent.yaml")
set_tests_properties(policy_error_tab_indentation PROPERTIES
  PASS_REGULAR_EXPRESSION "tab characters are not supported for indentation")

add_test(NAME policy_error_bad_indentation
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_indentation.yaml")
set_tests_properties(policy_error_bad_indentation PROPERTIES
  PASS_REGULAR_EXPRESSION "indentation does not match any enclosing block")

add_test(NAME policy_error_flow_mapping_unsupported
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_flow_mapping.yaml")
set_tests_properties(policy_error_flow_mapping_unsupported PROPERTIES
  PASS_REGULAR_EXPRESSION "flow mappings \\('\\{\\.\\.\\.\\}'\\) are not supported")

add_test(NAME policy_error_missing_policy_file
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${CMAKE_CURRENT_SOURCE_DIR}/tests/policies/does_not_exist.yaml")
set_tests_properties(policy_error_missing_policy_file PROPERTIES
  WILL_FAIL TRUE)

add_test(NAME policy_output_to_file
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --output "${CMAKE_CURRENT_BINARY_DIR}/policy_report.txt")
set_tests_properties(policy_output_to_file PROPERTIES
  FAIL_REGULAR_EXPRESSION "COMPLIANT")

# Regression tests for two real bugs found in code review before this feature was first committed
# (see each fixture's own header comment for the full story).
add_test(NAME policy_trailing_comma_in_flow_sequence
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/trailing_commas.yaml")
set_tests_properties(policy_trailing_comma_in_flow_sequence PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"trailing commas everywhere\"")

add_test(NAME policy_error_line_number_is_the_zones_own_line
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_overlap_after_description.yaml")
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
  PASS_REGULAR_EXPRESSION "needs exactly one of -r/--input.*or -i/--interface")

add_test(NAME live_capture_input_and_interface_are_mutually_exclusive_decode
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --interface lo)
set_tests_properties(live_capture_input_and_interface_are_mutually_exclusive_decode PROPERTIES
  WILL_FAIL TRUE)

add_test(NAME live_capture_requires_exactly_one_source_policy_validate
  COMMAND conduitscope policy validate --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(live_capture_requires_exactly_one_source_policy_validate PROPERTIES
  PASS_REGULAR_EXPRESSION "needs exactly one of -r/--input.*or -i/--interface")

add_test(NAME live_capture_input_and_interface_are_mutually_exclusive_policy_validate
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --interface lo --policy "${POLICY_DIR}/compliant.yaml")
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
