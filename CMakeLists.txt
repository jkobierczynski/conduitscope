# SPDX-License-Identifier: Apache-2.0
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
  src/stp.cpp
  src/can_socketcan.cpp
  src/devicenet.cpp
  src/bacnet.cpp
  src/hartip.cpp
  src/ffhse.cpp
  src/opcua.cpp
  src/cotp.cpp
  src/s7comm.cpp
  src/s7commplus.cpp
  src/mms.cpp
  src/mqtt.cpp
  src/dns.cpp
  src/nbns.cpp
  src/tls_sni.cpp
  src/rip.cpp
  src/igmp.cpp
  src/vrrp.cpp
  src/hsrp.cpp
  src/igrp.cpp
  src/pim.cpp
  src/eigrp.cpp
  src/ospf.cpp
  src/decoder.cpp
  src/resolver.cpp
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
# Data-link CRC-16 validation (header CRC + per-block CRC, both now actually calculated and
# compared against the on-the-wire value -- see dnp3_crc16 in dnp3.cpp). tools/make_sample_pcap.py
# now gives every sample_dnp3.pcap frame a genuinely correct CRC by default (dnp3_link_frame), so
# packets 1-12 above all validate cleanly; packets 13 and 14 below are deliberately corrupted.
# --------------------------------------------------------------------------

# Packet 1: a link-layer-only control frame with no user data at all -- must still get its header
# CRC checked (block_count/block_crc_failures stay 0, there is nothing to reassemble).
add_test(NAME dnp3_no_user_data_header_crc_still_validated
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_no_user_data_header_crc_still_validated PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 1,[^}]*\"dnp3_link_crc_valid\": true,\n    \"dnp3_header_crc_valid\": true,\n    \"dnp3_block_count\": 0,\n    \"dnp3_block_crc_failures\": 0")

# Data-link source/destination address (Dnp3LinkFrame::source/destination -- 16-bit DNP3 station
# addresses, NOT IP addresses, see decoder.hpp's own dnp3_source_address/dnp3_destination_address
# comment) surfaced to JSON output: packet 1 is master(1)->outstation(1024), packet 3 is the
# reverse direction, outstation(1024)->master(1) -- confirms both fields render correctly, and
# that the direction actually flips with the real traffic direction rather than being a fixed pair.
add_test(NAME dnp3_source_destination_address_master_to_outstation
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_source_destination_address_master_to_outstation PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 1,[^}]*\"dnp3_source_address\": 1,\n    \"dnp3_destination_address\": 1024,")

add_test(NAME dnp3_source_destination_address_outstation_to_master
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_source_destination_address_outstation_to_master PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 3,[^}]*\"dnp3_source_address\": 1024,\n    \"dnp3_destination_address\": 1,")

# Packet 2: single-block Read Class 0 request -- one valid block.
add_test(NAME dnp3_read_class0_crc_valid_single_block
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_read_class0_crc_valid_single_block PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 2,[^}]*\"dnp3_link_crc_valid\": true,\n    \"dnp3_header_crc_valid\": true,\n    \"dnp3_block_count\": 1,\n    \"dnp3_block_crc_failures\": 0")

# Packet 3: the 23-byte multi-block Response -- two valid blocks, exercising the multi-block CRC
# path (block boundary at 16 bytes) with genuinely correct CRCs, not just correct block placement.
add_test(NAME dnp3_multiblock_response_crc_valid_two_blocks
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_multiblock_response_crc_valid_two_blocks PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 3,[^}]*\"dnp3_link_crc_valid\": true,\n    \"dnp3_header_crc_valid\": true,\n    \"dnp3_block_count\": 2,\n    \"dnp3_block_crc_failures\": 0")

# Packet 13: the same Read Class 0 request as packet 2, but with a deliberately corrupted header
# CRC. The specific calculated-vs-declared note must appear, AND the application layer -- which a
# bad HEADER crc has no bearing on -- must still decode exactly as it does for packet 2, proving
# a CRC failure never stops decoding (this codebase's consistent degrade-gracefully philosophy).
add_test(NAME dnp3_bad_header_crc_noted_and_still_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_bad_header_crc_noted_and_still_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "function=Read \\(0x01\\) objects: \\[g60v1\\]\n *note: header CRC mismatch: calculated 0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f], frame declares 0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]")

add_test(NAME dnp3_bad_header_crc_fields_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_bad_header_crc_fields_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 13,[^}]*\"dnp3_link_crc_valid\": false,\n    \"dnp3_header_crc_valid\": false,\n    \"dnp3_block_count\": 1,\n    \"dnp3_block_crc_failures\": 0")

# Packet 14: the same 23-byte multi-block Response as packet 3, but with ONLY block 2's CRC
# corrupted (block 1's CRC and the header CRC are both left correct) -- confirms per-block
# granularity, and that object headers still decode from the (structurally untouched) bytes.
add_test(NAME dnp3_bad_block_crc_noted_and_objects_still_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format text)
set_tests_properties(dnp3_bad_block_crc_noted_and_objects_still_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "block 2 CRC mismatch \\(7 data byte\\(s\\)\\): calculated 0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f], frame declares 0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]\n.*object 0: g1v2 \\(Binary Input\\)"
  FAIL_REGULAR_EXPRESSION "block 1 CRC mismatch")

add_test(NAME dnp3_bad_block_crc_fields_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --format json)
set_tests_properties(dnp3_bad_block_crc_fields_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 14,[^}]*\"dnp3_link_crc_valid\": false,\n    \"dnp3_header_crc_valid\": true,\n    \"dnp3_block_count\": 2,\n    \"dnp3_block_crc_failures\": 1")

# Real-world confirmation, independent of the synthetic fixture above: a genuine capture's own
# CRC bytes (computed by a real DNP3 stack, not by tools/make_sample_pcap.py) must validate --
# this is a strong end-to-end check that the algorithm/table genuinely matches the DNP3 spec, not
# just conduitscope's own generator.
add_test(NAME real_dnp3_read_link_crc_valid
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_read.pcap" --format json)
set_tests_properties(real_dnp3_read_link_crc_valid PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_link_crc_valid\": true")

# Same, but for a link-layer-only control frame (Request Link Status carries no user data) --
# regression guard for the "no user data" path specifically, since that's the one case where
# process_dnp3_frame is never called at all (see decoder.cpp) and the crc fields must still be
# populated correctly from try_parse_dnp3_link_layer alone.
add_test(NAME real_dnp3_request_link_status_crc_valid_with_no_user_data
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_request_link_status.pcap" --format json)
set_tests_properties(real_dnp3_request_link_status_crc_valid_with_no_user_data PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_link_crc_valid\": true")

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
  PASS_REGULAR_EXPRESSION "g50v1 \\(Time and Date\\).*idx=0: 2006-08-25T15:56:00.890Z \\(1156521360890ms-since-epoch\\)")

# Same real Write request's Group 50 timestamp, now asserting the calendar-date rendering is
# present (not just the raw millisecond count) in both text and JSON output -- 1156521360890ms
# since the Unix epoch is 2006-08-25T15:56:00.890Z (computed independently of conduitscope, via
# Python's datetime.utcfromtimestamp, not just eyeballed) -- see decode_absolute_time48 in
# dnp3.cpp, which now reuses mqtt.hpp's format_millis_epoch for this rendering.
add_test(NAME real_dnp3_write_timestamp_calendar_date_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/dnp3/dnp3_write.pcap" --format json)
set_tests_properties(real_dnp3_write_timestamp_calendar_date_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dnp3_values\": \\[\"g50v1 idx=0: 2006-08-25T15:56:00.890Z \\(1156521360890ms-since-epoch\\)\"\\]")

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

# --------------------------------------------------------------------------
# The 21 ASDU type IDs added to the information-element decode table (synthetic,
# tests/sample_iec104_extended_types.pcap) -- see tools/make_sample_pcap.py's
# build_iec104_extended_types_sample for the exact byte layout each assertion below is checking.
# --------------------------------------------------------------------------
add_test(NAME iec104_step_position_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_step_position_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=500: position=-10 \\[T\\]\"\\]")

add_test(NAME iec104_step_position_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_step_position_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=501: position=50 @ 15:12\\.345\"\\]")

add_test(NAME iec104_step_position_time_tagged_cp56_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_step_position_time_tagged_cp56_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=502: position=-1 @ 2024-06-01 08:45:06\\.789 \\[OV\\]\"\\]")

add_test(NAME iec104_bitstring32_monitoring_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_bitstring32_monitoring_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=600: 0xDEADBEEF\"\\]")

add_test(NAME iec104_bitstring32_monitoring_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_bitstring32_monitoring_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=601: 0x0000FFFF @ 59:59\\.999 \\[IV\\]\"\\]")

add_test(NAME iec104_bitstring32_monitoring_time_tagged_cp56_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_bitstring32_monitoring_time_tagged_cp56_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=602: 0x12345678 @ 2025-12-31 23:59:59\\.000 \\[SU\\]\"\\]")

add_test(NAME iec104_measured_normalized_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_measured_normalized_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=700: 8192 \\(0\\.2500\\) @ 30:00\\.000\"\\]")

add_test(NAME iec104_measured_scaled_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_measured_scaled_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=701: -1234 @ 01:01\\.000 \\[IV\\] \\[OV\\]\"\\]")

add_test(NAME iec104_measured_short_float_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_measured_short_float_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=702: 100\\.500000 @ 45:45\\.123\"\\]")

add_test(NAME iec104_integrated_totals_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_integrated_totals_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=703: 123456 seq=5 @ 10:00\\.500 \\[CY\\]\"\\]")

add_test(NAME iec104_measured_normalized_no_quality_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_measured_normalized_no_quality_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=704: -16384 \\(-0\\.5000\\)\"\\]")

add_test(NAME iec104_bitstring32_command_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_bitstring32_command_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=800: 0xFFFFFFFF\"\\]")

add_test(NAME iec104_regulating_step_command_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_regulating_step_command_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=801: step up/higher qualifier=2 \\(long pulse duration\\) \\[Execute\\] @ 2023-01-01 00:00:00\\.000\"\\]")

add_test(NAME iec104_scaled_setpoint_command_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_scaled_setpoint_command_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=802: 5000 ql=50 \\[Select\\] @ 2022-07-04 12:00:00\\.000\"\\]")

add_test(NAME iec104_bitstring32_command_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_bitstring32_command_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=803: 0xCAFEBABE @ 2021-11-11 11:11:11\\.000\"\\]")

add_test(NAME iec104_delay_acquisition_command_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_delay_acquisition_command_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=804: 5000 ms\"\\]")

add_test(NAME iec104_test_command_time_tagged_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_test_command_time_tagged_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=805: test sequence=0x55AA @ 2020-02-29 03:03:03\\.003\"\\]")

add_test(NAME iec104_parameter_normalized_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_parameter_normalized_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=900: 16384 \\(0\\.5000\\) KPA=1 \\(threshold value\\) \\[LPC\\]\"\\]")

add_test(NAME iec104_parameter_scaled_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_parameter_scaled_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=901: -100 KPA=3 \\(low limit for transmission\\) \\[POP\\]\"\\]")

add_test(NAME iec104_parameter_short_float_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_parameter_short_float_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=902: 2\\.500000 KPA=4 \\(high limit for transmission\\) \\[LPC\\] \\[POP\\]\"\\]")

add_test(NAME iec104_parameter_activation_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_extended_types.pcap")
set_tests_properties(iec104_parameter_activation_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"iec104_objects\": \\[\"ioa=903: act/deact of the parameter of the addressed object\"\\]")

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
  PASS_REGULAR_EXPRESSION "\\[tcp\\]  TCP payload of 24 byte\\(s\\) on port 52001->44818 did not match OPC UA, EtherNet/IP, IEC 104, Modbus, DNP3, COTP/S7comm/MMS, HART-IP, MQTT, or FF-HSE")

# --------------------------------------------------------------------------
# EtherNet/IP CIP STRING/SHORT_STRING and Structured Data Type (UDT/array-of-UDT tag) value
# decoding, synthetic (tests/sample_enip_string_and_structured.pcap) -- see
# tools/make_sample_pcap.py's build_enip_string_and_structured_sample for the exact byte layout
# each assertion below is checking.
# --------------------------------------------------------------------------
add_test(NAME enip_string_read_tag_response_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_string_and_structured.pcap")
set_tests_properties(enip_string_read_tag_response_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"enip_cip_values\": \\[\"type=STRING\", \"PumpFault\"\\]")

add_test(NAME enip_short_string_write_tag_request_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_string_and_structured.pcap")
set_tests_properties(enip_short_string_write_tag_request_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"enip_cip_values\": \\[\"type=SHORT_STRING element_count=1\", \"OK\"\\]")

add_test(NAME enip_empty_string_read_tag_response_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_string_and_structured.pcap")
set_tests_properties(enip_empty_string_read_tag_response_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"enip_cip_values\": \\[\"type=STRING\", \"\"\\]")

add_test(NAME enip_structured_read_tag_response_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_string_and_structured.pcap")
set_tests_properties(enip_structured_read_tag_response_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"enip_cip_values\": \\[\"type=Structured Data Type \\(0x02A0\\)\", \"structure_handle=0x1234\"\\],\n    \"notes\": \\[\"UDT/structured member data \\(6 byte\\(s\\)\\) not value-decoded -- this decoder has no access to the tag's Template definition \\(member names/types/offsets\\), obtained separately via Get_Attribute_List against the Template object: 01 00 2a 00 00 00\"\\]")

add_test(NAME enip_structured_write_tag_request_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_string_and_structured.pcap")
set_tests_properties(enip_structured_write_tag_request_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"enip_cip_values\": \\[\"type=Structured Data Type \\(0x02A0\\) element_count=1\", \"structure_handle=0x1234\"\\]")

# Regression: before cip_is_plausible_type_code was widened to include the >= 0x02A0 structured
# range (see that function's comment in enip.cpp), a genuine UDT Read_Tag response like the one
# above was WRONGLY rejected into the "response data does not start with a recognized CIP
# elementary type code" fallback note -- assert the structure_handle value is present AND that
# fallback note is absent for this specific response.
add_test(NAME enip_structured_type_code_not_misclassified_as_implausible
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip_string_and_structured.pcap")
set_tests_properties(enip_structured_type_code_not_misclassified_as_implausible PROPERTIES
  PASS_REGULAR_EXPRESSION "structure_handle=0x1234"
  FAIL_REGULAR_EXPRESSION "response data does not start with a recognized CIP elementary type code")

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
  PASS_REGULAR_EXPRESSION "sqNum=10.*sqNum=11.*sqNum=12.*sqNum=1 ")

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
  PASS_REGULAR_EXPRESSION "non-ip\\][^\n]*\n *eth [^\n]*\n#11[^\n]*non-ip\\]")

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
# STP/RSTP/MSTP (synthetic, tests/sample_stp.pcap): the first protocol in this codebase reached
# via classic IEEE 802.3 length-framed LLC (DSAP=SSAP=0x42, Control=0x03) rather than a DIX
# EtherType -- see link_layer.hpp's file header for that plumbing, and stp.hpp's file header for
# the BPDU wire format and every documented deviation/scope decision. Packet numbers in comments
# below match build_stp_sample()'s own numbered comments 1-30 in tools/make_sample_pcap.py.
# --------------------------------------------------------------------------

# 1) Classic Configuration BPDU (version 0) -- byte-for-byte reproduction of a real capture frame
# (see real_stp_plant1_* below), including the 8 bytes of Ethernet minimum-frame-size padding.
add_test(NAME stp_baseline_config_bpdu_matches_real_capture_frame
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_baseline_config_bpdu_matches_real_capture_frame PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[stp\\]  STP Configuration: Root=32768/80/64:a0:e7:9a:05:80 Cost=4 Bridge=32768/80/64:ae:0c:34:a3:80 Port=0x8083\n *note: 8 trailing byte\\(s\\) after the 802.3 Length field's declared LLC client-data length were trimmed")

# 2) RSTP RST BPDU (version 2) -- byte-for-byte reproduction of a real capture frame (see
# real_stp_mms_and_goose_* below).
add_test(NAME stp_baseline_rst_bpdu_matches_real_capture_frame
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_baseline_rst_bpdu_matches_real_capture_frame PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[stp\\]  RSTP BPDU: Root=28672/4095/00:40:15:18:1d:7c Cost=1100 Bridge=32768/0/00:0a:dc:06:19:5c Port=0x8010 Role=Designated \\[Learning\\] \\[Forwarding\\]\n *note: 7 trailing byte\\(s\\)")

# 3-4) TCN BPDU, decoded under both a classic STP (version 0) and an RSTP (version 2) Protocol
# Version byte -- TCN BPDUs carry no version-specific body, only the version name in the summary
# differs.
add_test(NAME stp_tcn_under_stp_version_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_tcn_under_stp_version_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#3  .*\\[stp\\]  STP Topology Change Notification \\(STP \\(802.1D\\)\\)")

add_test(NAME stp_tcn_under_rstp_version_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_tcn_under_rstp_version_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#4  .*\\[stp\\]  STP Topology Change Notification \\(RSTP \\(802.1w\\)\\)")

# 5) Classic Configuration BPDU with the Topology Change and Topology Change Acknowledgment flags
# both set.
add_test(NAME stp_config_tc_and_tca_flags_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_config_tc_and_tca_flags_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#5  .*\\[TC\\] \\[TCA\\]")

add_test(NAME stp_config_tc_and_tca_flags_decoded_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap")
set_tests_properties(stp_config_tc_and_tca_flags_decoded_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 5,.*\"stp_flags\": 129,.*\"stp_flag_tca\": true,.*\"stp_flag_tc\": true,")

# 6) Configuration BPDU (Type 0x00) under an unusual Protocol Version (2, RSTP's version) --
# decoded structurally anyway, with a note flagging the unusual combination.
add_test(NAME stp_config_bpdu_unusual_version_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_config_bpdu_unusual_version_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "#6  .*\\[stp\\]  Configuration BPDU \\(version 2\\):.*\n *note: BPDU Type 0x00 \\(Configuration\\) with Protocol Version 2")

# 7) RST/MST-shaped BPDU (Type 0x02) under Protocol Version 0 (STP's version) -- decoded as a
# plain STP-labeled BPDU with no RST-specific role/flag rendering (Port Role always "Unknown"
# because the flags byte isn't RST-shaped under version 0).
add_test(NAME stp_type_0x02_under_stp_version_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_type_0x02_under_stp_version_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#7  .*\\[stp\\]  STP \\(802.1D\\) BPDU: Root=32768/0/00:1a:2b:3c:4d:5f Cost=0 Bridge=32768/0/00:1a:2b:3c:4d:5f Port=0x8005 Role=Unknown")

# 8-11) RST BPDU Port Role coverage: Root+Proposal, Alternate/Backup+TC+Agreement, Unknown (all
# role bits clear), Designated+Learning+Forwarding.
add_test(NAME stp_rst_port_role_root_with_proposal_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_rst_port_role_root_with_proposal_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#8  .*Root=4096/10/00:1a:2b:3c:4d:5e Cost=200000 Bridge=32768/0/00:1a:2b:3c:4d:5f Port=0x8007 Role=Root \\[Proposal\\]")

add_test(NAME stp_rst_port_role_alternate_backup_with_tc_and_agreement_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_rst_port_role_alternate_backup_with_tc_and_agreement_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#9  .*Port=0x8009 Role=Alternate/Backup \\[TC\\] \\[Agreement\\]")

add_test(NAME stp_rst_port_role_unknown_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_rst_port_role_unknown_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#10  .*Port=0x8001 Role=Unknown")

add_test(NAME stp_rst_port_role_designated_learning_forwarding_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_rst_port_role_designated_learning_forwarding_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#11  .*Port=0x8002 Role=Designated \\[Learning\\] \\[Forwarding\\]")

# 12) MSTP MST BPDU with two MSTI Configuration Messages -- full MST extension: MST Config Name,
# Revision Level, digest, CIST Bridge Identifier/Remaining Hops, and both MSTI messages' own
# Regional Root/Cost/Bridge+Port Identifier Priority nibble/Remaining Hops/role+flags.
add_test(NAME stp_mstp_two_msti_messages_summary_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_mstp_two_msti_messages_summary_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#12  .*MSTP BPDU: CIST Root=32768/100/00:1a:2b:3c:4d:5e Cost=50 CIST RegionalRoot=32768/100/00:1a:2b:3c:4d:5e Bridge=32768/100/00:1a:2b:3c:4d:5e MSTIs=2")

add_test(NAME stp_mstp_two_msti_messages_full_fields_in_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap")
set_tests_properties(stp_mstp_two_msti_messages_full_fields_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 12,.*\"stp_version_3_length\": 96,.*\"stp_mst_config_name\": \"region-1\",.*\"stp_mst_config_revision_level\": 3,.*\"stp_mst_config_digest\": \"00112233445566778899aabbccddeeff\",.*\"stp_cist_internal_root_path_cost\": 50,.*\"stp_cist_remaining_hops\": 19,.*\"stp_msti_messages\": \\[\"MSTID=10 RegionalRoot=32768/00:1a:2b:3c:4d:5e Cost=20000 BridgePrio=8 PortPrio=8 RemainingHops=20 Role=Designated \\[Learning\\] \\[Forwarding\\]\", \"MSTID=20 RegionalRoot=4096/00:1a:2b:3c:4d:5f Cost=0 BridgePrio=0 PortPrio=0 RemainingHops=20 Role=Unknown\"\\]")

# 13) MSTP MST BPDU with zero MSTI Configuration Messages (Version 3 Length exactly the 64-byte
# static MST extension header, no MSTI messages appended).
add_test(NAME stp_mstp_zero_msti_messages_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_mstp_zero_msti_messages_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#13  .*MSTIs=0")

# 14) Version 3 Length nonzero but less than the 64-byte static MST extension header -- the
# reference dissector's own Cisco-C3550-firmware work-around: reinterpreted as a COUNT OF
# MESSAGES rather than bytes.
add_test(NAME stp_mstp_version3_length_below_64_cisco_workaround_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_mstp_version3_length_below_64_cisco_workaround_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "#14  .*MSTIs=2\n *note: Version 3 Length \\(2\\) is nonzero but less than the 64-byte static MST extension header -- treated as a COUNT OF MESSAGES")

# 15) Version 3 Length implies more MSTI bytes than actually remain -- decodes as many whole
# messages as fit.
add_test(NAME stp_mstp_partial_msti_bytes_decodes_whole_messages_that_fit
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_mstp_partial_msti_bytes_decodes_whole_messages_that_fit PROPERTIES
  PASS_REGULAR_EXPRESSION "#15  .*MSTIs=1\n *note: Version 3 Length implies 32 byte\\(s\\) of MSTI Configuration Message\\(s\\) but only 16 byte\\(s\\) remain -- decoding as many whole messages as fit")

# 16) A partial trailing MSTI Configuration Message (fewer than 16 leftover bytes) is left
# undecoded and its leftover bytes are noted, not silently dropped.
add_test(NAME stp_mstp_trailing_partial_msti_message_ignored_and_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_mstp_trailing_partial_msti_message_ignored_and_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "#16  .*MSTIs=1\n *note: Version 3 Length implies a partial trailing MSTI Configuration Message \\(4 byte\\(s\\) leftover\\) -- not decoded\n *note: 4 byte\\(s\\) remain after the last decoded MSTI Configuration Message -- ignored")

# 17) Protocol Version 3 (MSTP) but too few bytes present for the MST extension's 102-byte
# minimum -- falls back to a plain RST-shaped decode, matching the reference dissector.
add_test(NAME stp_mstp_too_short_for_mst_extension_falls_back_to_rst
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_mstp_too_short_for_mst_extension_falls_back_to_rst PROPERTIES
  PASS_REGULAR_EXPRESSION "#17  .*Port=0x800A Role=Unknown\n *note: Protocol Version 3 but only 36 byte\\(s\\) present \\(need >= 102\\) -- MST extension not attempted, decoded as a plain RST BPDU")

# 18) Protocol Version 3 but Version 1 Length is nonzero -- the MST detection gate's second
# condition fails, falls back to a plain RST-shaped decode (matches the reference source exactly).
add_test(NAME stp_mstp_nonzero_version1_length_falls_back_to_rst
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_mstp_nonzero_version1_length_falls_back_to_rst PROPERTIES
  PASS_REGULAR_EXPRESSION "#18  .*Port=0x800B Role=Unknown\n *note: Protocol Version 3 but Version 1 Length is 5 \\(not 0\\) -- MST extension not attempted, decoded as a plain RST BPDU \\(matches the reference source's own behavior exactly\\)")

# 19) Version 3 Length is 0 (not merely below 64) and the frame's total length matches the
# legacy/alternative MSTI Configuration Message format's own sizing rule -- named as such, but
# that alternative format is deliberately not decoded (see stp.hpp for why).
add_test(NAME stp_mstp_version3_length_zero_alt_format_named_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_mstp_version3_length_zero_alt_format_named_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#19  .*MST Config Name=\"\" \\(CIST Bridge Identifier/MSTI not decoded -- Version 3 Length is 0, see notes\\)\n *note: Version 3 Length is 0 and the frame's total length matches the legacy/alternative MSTI Configuration Message format's own sizing rule")

# 20) SPB (802.1aq, Protocol Version 4) -- named-only, not decoded, per this release's explicit
# scope decision (see stp.hpp).
add_test(NAME stp_spb_version4_named_only_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_spb_version4_named_only_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#20  .*\\[stp\\]  SPB \\(802.1aq\\), not decoded -- out of scope")

# 21-22) STP's own LLC DSAP/SSAP/Control (0x42/0x42/0x03) present, but the payload itself doesn't
# structurally parse as STP (bad Protocol Identifier; unrecognized BPDU Type) -- falls back to
# reporting the frame as a generic, unrecognized LLC frame rather than guessing.
add_test(NAME stp_bad_protocol_identifier_and_bad_bpdu_type_fall_back_to_llc
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_bad_protocol_identifier_and_bad_bpdu_type_fall_back_to_llc PROPERTIES
  PASS_REGULAR_EXPRESSION "#21  .*\\[non-ip\\]  IEEE 802.3 LLC frame, DSAP=0x42 SSAP=0x42 Control=0x3 \\(length=38\\)\n *eth [^\n]*\n#22  .*\\[non-ip\\]  IEEE 802.3 LLC frame, DSAP=0x42 SSAP=0x42 Control=0x3 \\(length=38\\)")

# 23) Truncated before the common Configuration/RST BPDU body -- reported as truncated with an
# explanatory note, not decoded further.
add_test(NAME stp_truncated_before_common_body_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_truncated_before_common_body_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "#23  .*\\[stp\\]  Configuration BPDU \\(truncated before the common body\\)\n *note: only 20 byte\\(s\\) present, need 35 for the common Configuration/RST BPDU body")

# 24) Common body present in full, but truncated right after it (no Version 1 Length byte at
# all) -- decoded as RST-shaped with no trailer.
add_test(NAME stp_truncated_with_no_version1_length_byte_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_truncated_with_no_version1_length_byte_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "#24  .*RST/MST BPDU \\(RSTP \\(802.1w\\)\\): Root=32768/0/00:1a:2b:3c:4d:5e Cost=0 Bridge=32768/0/00:1a:2b:3c:4d:5e \\(truncated -- no Version 1 Length\\)\n *note: Version 1 Length byte \\(offset 35\\) missing")

# 25-28) Out-of-scope/unrecognized LLC traffic that must not crash and must not be misreported as
# STP: SNAP-encapsulated Cisco PVST+, GARP (GVRP/GMRP, which collides with STP's own DSAP/SSAP and
# is disambiguated only by destination MAC), an unrelated LLC DSAP/SSAP pair, and a length-framed
# frame too short for even a 3-byte LLC header.
add_test(NAME stp_cisco_pvst_plus_named_only_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_cisco_pvst_plus_named_only_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#25  .*\\[non-ip\\]  Cisco PVST\\+ \\(SNAP-encapsulated, not decoded\\)")

add_test(NAME stp_garp_disambiguated_by_dest_mac_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_garp_disambiguated_by_dest_mac_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#26  .*\\[non-ip\\]  GARP \\(GVRP/GMRP\\) -- shares STP's Bridge Group Address DSAP/SSAP \\(0x42/0x42\\), disambiguated by destination MAC, not decoded")

add_test(NAME stp_unrecognized_llc_dsap_ssap_reported_generically
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_unrecognized_llc_dsap_ssap_reported_generically PROPERTIES
  PASS_REGULAR_EXPRESSION "#27  .*\\[non-ip\\]  IEEE 802.3 LLC frame, DSAP=0xE0 SSAP=0xE0 Control=0x3 \\(length=13\\)")

add_test(NAME stp_too_short_for_llc_header_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_too_short_for_llc_header_does_not_crash PROPERTIES
  PASS_REGULAR_EXPRESSION "#28  .*\\[non-ip\\]  IEEE 802.3 frame, length=5 \\(too short for an LLC header\\)")

# 29-30) The 802.3 Length field itself is implausible (too small to even cover the already-
# consumed LLC header, or larger than the bytes actually captured) -- parse_ethernet falls back to
# using whatever bytes are actually present, and the TCN BPDU underneath still decodes correctly
# either way.
add_test(NAME stp_implausibly_small_length_field_still_decodes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_implausibly_small_length_field_still_decodes PROPERTIES
  PASS_REGULAR_EXPRESSION "#29  .*\\[stp\\]  STP Topology Change Notification \\(STP \\(802.1D\\)\\)")

add_test(NAME stp_length_field_exceeds_captured_bytes_still_decodes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(stp_length_field_exceeds_captured_bytes_still_decodes PROPERTIES
  PASS_REGULAR_EXPRESSION "#30  .*\\[stp\\]  STP Topology Change Notification \\(STP \\(802.1D\\)\\)")

# Stats accumulation across the whole synthetic fixture.
add_test(NAME stp_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --stats)
set_tests_properties(stp_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "stp bpdu types:\n *Configuration +4\n *Rapid/Multiple Spanning Tree +16\n *Topology Change Notification +4\nstp protocol versions:\n *MSTP \\(802.1s\\) +8\n *RSTP \\(802.1w\\) +8\n *SPB \\(802.1aq\\) +1\n *STP \\(802.1D\\) +7\nstp mst bpdus \\(full mst extension decoded\\): 6\nstp msti configuration messages \\(summed across every mst bpdu\\): 6\nstp topology change flag set: 2")

# --------------------------------------------------------------------------
# Real-world STP/RSTP captures -- see tests/real_captures/stp/ATTRIBUTION.md for provenance.
# --------------------------------------------------------------------------

# plant1_stp_only.pcap: 42 real classic Configuration BPDUs (version 0), all steady-state, all
# identical Root/Bridge/Cost/Port, trimmed with `tshark -Y stp -w` from a much larger capture
# (see ATTRIBUTION.md for why the trim was necessary and how it preserves the original bytes).
add_test(NAME real_stp_plant1_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/stp/plant1_stp_only.pcap")

add_test(NAME real_stp_plant1_config_bpdu_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/stp/plant1_stp_only.pcap" --format text)
set_tests_properties(real_stp_plant1_config_bpdu_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[stp\\]  STP Configuration: Root=32768/80/64:a0:e7:9a:05:80 Cost=4 Bridge=32768/80/64:ae:0c:34:a3:80 Port=0x8083")

add_test(NAME real_stp_plant1_all_42_frames_decoded_as_stp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/stp/plant1_stp_only.pcap" --stats)
set_tests_properties(real_stp_plant1_all_42_frames_decoded_as_stp PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +42.*protocols:\n *stp +42.*stp bpdu types:\n *Configuration +42")

add_test(NAME real_stp_plant1_padding_trimmed_note_present
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/stp/plant1_stp_only.pcap" --format text)
set_tests_properties(real_stp_plant1_padding_trimmed_note_present PROPERTIES
  PASS_REGULAR_EXPRESSION "note: 8 trailing byte\\(s\\) after the 802.3 Length field's declared LLC client-data length were trimmed")

# sample_file_mms_and_goose.pcap: 12 real RSTP RST BPDUs (version 2, steady-state Designated
# [Learning] [Forwarding] on both bridge ports 0x8010 and 0x8013) mixed in with unrelated
# MMS/GOOSE/NTP/SMB traffic -- confirms the STP decoder correctly ignores everything else in a
# realistic, protocol-mixed capture.
add_test(NAME real_stp_mms_and_goose_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/stp/sample_file_mms_and_goose.pcap")

add_test(NAME real_stp_mms_and_goose_rst_bpdu_port_8010_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/stp/sample_file_mms_and_goose.pcap" --format text)
set_tests_properties(real_stp_mms_and_goose_rst_bpdu_port_8010_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[stp\\]  RSTP BPDU: Root=28672/4095/00:40:15:18:1d:7c Cost=1100 Bridge=32768/0/00:0a:dc:06:19:5c Port=0x8010 Role=Designated \\[Learning\\] \\[Forwarding\\]")

add_test(NAME real_stp_mms_and_goose_rst_bpdu_port_8013_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/stp/sample_file_mms_and_goose.pcap" --format text)
set_tests_properties(real_stp_mms_and_goose_rst_bpdu_port_8013_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[stp\\]  RSTP BPDU: Root=28672/4095/00:40:15:18:1d:7c Cost=1100 Bridge=32768/0/00:0a:dc:06:19:5c Port=0x8013 Role=Designated \\[Learning\\] \\[Forwarding\\]")

add_test(NAME real_stp_mms_and_goose_exactly_12_stp_frames
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/stp/sample_file_mms_and_goose.pcap" --stats)
set_tests_properties(real_stp_mms_and_goose_exactly_12_stp_frames PROPERTIES
  PASS_REGULAR_EXPRESSION "stp +12.*stp bpdu types:\n *Rapid/Multiple Spanning Tree +12")

add_test(NAME real_stp_mms_and_goose_json_fields_present
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/stp/sample_file_mms_and_goose.pcap")
set_tests_properties(real_stp_mms_and_goose_json_fields_present PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"stp\",.*\"stp_protocol_version_name\": \"RSTP \\(802.1w\\)\",.*\"stp_bpdu_type_name\": \"Rapid/Multiple Spanning Tree\",.*\"stp_root_mac\": \"00:40:15:18:1d:7c\",.*\"stp_bridge_mac\": \"00:0a:dc:06:19:5c\",")

# --------------------------------------------------------------------------
# DeviceNet over SocketCAN (synthetic, tests/sample_devicenet.pcap) -- LINKTYPE_CAN_SOCKETCAN
# (227), this codebase's second wholly new link layer after STP's own classic-802.3-LLC work
# above, and a wholly SEPARATE one from Ethernet (no MAC addresses, no IP layer at all -- see
# can_socketcan.hpp/devicenet.hpp's own file header comments). No real public DeviceNet/CAN
# capture was found during this feature's own research (searched github.com/ITI/ICS-Security-
# Tools and general web search for "DeviceNet pcap"/"CAN capture" -- ICS-Security-Tools' own
# pcaps/README.md lists no CAN-bus or DeviceNet capture of any kind among its protocol-organized
# captures, and no other public source turned one up either) -- synthetic-only, matching several
# other protocols already in this codebase (e.g. FOUNDATION Fieldbus HSE, per ffhse.hpp). Packet
# numbers in comments below match build_devicenet_sample()'s own numbered comments 1-33 in
# tools/make_sample_pcap.py.
# --------------------------------------------------------------------------

# 1-4) Group 1: all four named message types, with Source MAC ID extraction (id & 0x003F) and
# I/O data shown as raw byte count only (never further decoded).
add_test(NAME devicenet_group1_multicast_poll_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group1_multicast_poll_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#1  .*\\[devicenet\\]  DeviceNet Group 1 \\(Slave's I/O Multicast Poll Response\\): SrcMAC=5 CAN ID=0x0305 I/O data=4 byte\\(s\\) \\(not decoded further\\)")

add_test(NAME devicenet_group1_change_of_state_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group1_change_of_state_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#2  .*DeviceNet Group 1 \\(Slave's I/O Change of State or Cyclic Message\\): SrcMAC=12 CAN ID=0x034C")

add_test(NAME devicenet_group1_bit_strobe_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group1_bit_strobe_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#3  .*DeviceNet Group 1 \\(Slave's I/O Bit-Strobe Response Message\\): SrcMAC=0 CAN ID=0x0380 I/O data=0 byte\\(s\\)")

add_test(NAME devicenet_group1_poll_response_or_cos_ack_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group1_poll_response_or_cos_ack_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#4  .*DeviceNet Group 1 \\(Slave's I/O Poll Response or COS/Cyclic Ack Message\\): SrcMAC=63 CAN ID=0x03FF I/O data=8 byte\\(s\\)")

# 5) Group 1, unnamed message-ID sub-value -- falls back to "Other Group 1 Message".
add_test(NAME devicenet_group1_other_message_fallback
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group1_other_message_fallback PROPERTIES
  PASS_REGULAR_EXPRESSION "#5  .*DeviceNet Group 1 \\(Other Group 1 Message\\): SrcMAC=7 CAN ID=0x0047")

# 6-9) Group 2: several named message types, with Source MAC ID extraction ((id & 0x01F8) >> 3).
add_test(NAME devicenet_group2_bit_strobe_command_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group2_bit_strobe_command_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#6  .*DeviceNet Group 2 \\(Master's I/O Bit-Strobe Command Message\\): SrcMAC=20 CAN ID=0x04A0")

add_test(NAME devicenet_group2_explicit_unconnected_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group2_explicit_unconnected_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#7  .*DeviceNet Group 2 \\(Slave's Explicit/Unconnected Response Messages\\): SrcMAC=3 CAN ID=0x041B")

add_test(NAME devicenet_group2_explicit_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group2_explicit_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#8  .*DeviceNet Group 2 \\(Master's Explicit Request Messages\\): SrcMAC=10 CAN ID=0x0454")

add_test(NAME devicenet_group2_only_unconnected_explicit_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group2_only_unconnected_explicit_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#9  .*DeviceNet Group 2 \\(Group 2 Only Unconnected Explicit Request Messages\\): SrcMAC=45 CAN ID=0x056E")

# 10-11) Group 2 Duplicate MAC ID Check Messages, both directions, with the full optional payload
# decode (RR bit, Physical Port Number, little-endian Vendor ID, little-endian Serial Number).
add_test(NAME devicenet_dup_mac_id_check_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_dup_mac_id_check_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#10  .*DeviceNet Group 2 \\(Duplicate MAC ID Check Messages\\): SrcMAC=7 CAN ID=0x043F Request PhysicalPort=2 VendorID=0xAB Serial=305419896")

add_test(NAME devicenet_dup_mac_id_check_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_dup_mac_id_check_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#11  .*DeviceNet Group 2 \\(Duplicate MAC ID Check Messages\\): SrcMAC=7 CAN ID=0x043F Response PhysicalPort=1 VendorID=0x1234 Serial=3405691582")

add_test(NAME devicenet_dup_mac_id_check_json_fields_present
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap")
set_tests_properties(devicenet_dup_mac_id_check_json_fields_present PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 10,.*\"devicenet_dup_mac_id_is_response\": false,.*\"devicenet_dup_mac_id_physical_port_number\": 2,.*\"devicenet_dup_mac_id_vendor_id\": 171,.*\"devicenet_dup_mac_id_serial_number\": 305419896,")

# 12) Group 3, generic "Group 3 Message", Source MAC ID extraction (id & 0x3F, NOT shifted --
# unlike Group 2's own shifted extraction), and a GENERIC CIP service code (0x0E,
# Get_Attribute_Single) reused directly from enip.hpp's cip_service_name.
add_test(NAME devicenet_group3_generic_message_generic_cip_service_reused
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group3_generic_message_generic_cip_service_reused PROPERTIES
  PASS_REGULAR_EXPRESSION "#12  .*DeviceNet Group 3 \\(Group 3 Message\\): SrcMAC=9 CAN ID=0x0609 DestMAC=15 Request Service=Get_Attribute_Single \\(2 byte\\(s\\) of request/response data, not decoded")

# 13-16) Group 3 explicit messaging using DeviceNet's own four service codes (0x4B-0x4E) --
# distinct from EtherNet/IP's own unrelated use of some of the same numeric values (see
# devicenet.hpp/cip_service_name's own comment in enip.cpp).
add_test(NAME devicenet_group3_open_explicit_message_connection_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group3_open_explicit_message_connection_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#13  .*DeviceNet Group 3 \\(Unconnected Explicit Request Message\\): SrcMAC=12 CAN ID=0x078C DestMAC=20 Request Service=Open Explicit Message Connection Request")

add_test(NAME devicenet_group3_close_connection_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group3_close_connection_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#14  .*DeviceNet Group 3 \\(Unconnected Explicit Response Message\\): SrcMAC=20 CAN ID=0x0754 DestMAC=12 Response Service=Close Connection Request")

add_test(NAME devicenet_group3_device_heartbeat_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group3_device_heartbeat_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#15  .*Service=Device Heartbeat Message")

add_test(NAME devicenet_group3_device_shutdown_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group3_device_shutdown_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#16  .*Service=Device Shutdown Message")

add_test(NAME devicenet_group3_cip_service_json_fields_present
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap")
set_tests_properties(devicenet_group3_cip_service_json_fields_present PROPERTIES
  PASS_REGULAR_EXPRESSION "\"index\": 14,.*\"devicenet_group\": 3,.*\"devicenet_dest_mac_id\": 12,.*\"devicenet_is_fragmented\": false,.*\"devicenet_cip_is_response\": true,.*\"devicenet_cip_service\": \"Close Connection Request\",")

# 17) Group 4, message-ID value not one of the four named ones -- "Reserved Group 4 Message".
add_test(NAME devicenet_group4_reserved_message_fallback
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group4_reserved_message_fallback PROPERTIES
  PASS_REGULAR_EXPRESSION "#17  .*DeviceNet Group 4 \\(Reserved Group 4 Message\\): CAN ID=0x07C5")

# 18) Group 3, XID flag set alongside a non-fragmented service byte.
add_test(NAME devicenet_group3_xid_flag_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group3_xid_flag_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#18  .*DestMAC=30 \\[XID\\] Request Service=Get_Attribute_Single")

# 19) Group 3, FRAGMENTED message -- not reassembled, matching Wireshark's own unimplemented TODO.
add_test(NAME devicenet_group3_fragmented_not_reassembled
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group3_fragmented_not_reassembled PROPERTIES
  PASS_REGULAR_EXPRESSION "#19  .*DestMAC=40 \\[Fragmented -- not reassembled, matches upstream's own unimplemented TODO, see devicenet.hpp\\]\n *note: Group 3 Fragmentation flag set")

# 20) Group 3, non-fragmented, but no service byte present -- tolerant partial decode.
add_test(NAME devicenet_group3_missing_service_byte_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group3_missing_service_byte_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "#20  .*DestMAC=11\n *note: Group 3 non-fragmented message but the CIP-style service/request-response byte")

# 21) Group 3 message with no payload at all -- CAN ID classification alone still succeeds.
add_test(NAME devicenet_group3_no_payload_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group3_no_payload_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "#21  .*DeviceNet Group 3 \\(Group 3 Message\\): SrcMAC=6 CAN ID=0x0606\n *note: Group 3 message with no payload at all")

# 22-25) Group 4, all four named message types (no MAC ID extraction defined for Group 4 at all).
add_test(NAME devicenet_group4_comm_faulted_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group4_comm_faulted_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#22  .*DeviceNet Group 4 \\(Communication Faulted Response Message\\): CAN ID=0x07EC")

add_test(NAME devicenet_group4_comm_faulted_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group4_comm_faulted_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#23  .*DeviceNet Group 4 \\(Communication Faulted Request Message\\): CAN ID=0x07ED")

add_test(NAME devicenet_group4_offline_ownership_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group4_offline_ownership_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#24  .*DeviceNet Group 4 \\(Offline Ownership Response Message\\): CAN ID=0x07EE")

add_test(NAME devicenet_group4_offline_ownership_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_group4_offline_ownership_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#25  .*DeviceNet Group 4 \\(Offline Ownership Request Message\\): CAN ID=0x07EF")

# 27) Unclassified CAN ID range (0x07F0-0x07FF) -- the reference dissector has no handling for
# this range at all; shown structurally only.
add_test(NAME devicenet_unclassified_id_range_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_unclassified_id_range_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "#27  .*DeviceNet frame, unclassified CAN ID range: CAN ID=0x07F5\n *note: CAN ID 0x07F5 falls in the 0x07F0-0x07FF range")

# 28-30) EFF/RTR/ERR frames -- NOT valid DeviceNet frame shapes, rejected exactly the way
# Wireshark's own packet-devicenet.c rejects them (its very first check).
add_test(NAME devicenet_eff_frame_rejected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_eff_frame_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "#28  .*\\[non-ip\\]  CAN frame, id=0x1ABCDEF \\[EFF -- extended 29-bit id\\] \\(not a valid DeviceNet frame shape\\)")

add_test(NAME devicenet_rtr_frame_rejected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_rtr_frame_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "#29  .*\\[non-ip\\]  CAN frame, id=0x305 \\[RTR -- remote transmission request\\] \\(not a valid DeviceNet frame shape\\)")

add_test(NAME devicenet_err_frame_rejected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_err_frame_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "#30  .*\\[non-ip\\]  CAN frame, id=0x0 \\[ERR -- error frame\\] \\(not a valid DeviceNet frame shape\\)")

# 31) CAN FD frame -- CAN-ID-derived classification still shown, but no payload semantic decode.
add_test(NAME devicenet_can_fd_frame_not_semantically_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_can_fd_frame_not_semantically_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "#31  .*DeviceNet Group 1 \\(Slave's I/O Multicast Poll Response\\): SrcMAC=9 CAN ID=0x0309\n *note: CAN FD frame \\(fd_flags 0x04 set\\)")

# 32) Truncated: fewer than the fixed 8-byte SocketCAN header itself is present -- must not
# crash; reported as a "parse-error" packet, the same tolerant handling an undersized Ethernet
# frame already gets from parse_ethernet.
add_test(NAME devicenet_truncated_header_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_truncated_header_does_not_crash PROPERTIES
  PASS_REGULAR_EXPRESSION "#32  .*\\[parse-error\\]  could not parse packet:")

# 33) Truncated payload: header fully present and declares Payload Length 8, but only 3 payload
# bytes actually follow -- exercises parse_socketcan_frame's own truncation-tolerant clamping
# (not a thrown ParseError, unlike packet 32 above).
add_test(NAME devicenet_truncated_payload_clamped_and_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_truncated_payload_clamped_and_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "#33  .*DeviceNet Group 1 \\(Slave's I/O Multicast Poll Response\\): SrcMAC=22 CAN ID=0x0316 I/O data=3 byte\\(s\\) \\(not decoded further\\)\n *note: Payload Length declares 8 byte\\(s\\) but only 3 byte\\(s\\) remain in the captured record -- payload clamped to what was actually captured")

# --protocol devicenet: an ordinary Ethernet-linktype capture (sample_stp.pcap) is completely
# unaffected -- DeviceNet dispatch is gated on link_type == LINKTYPE_CAN_SOCKETCAN, checked
# BEFORE any protocol filter, so restricting to --protocol devicenet on a non-CAN capture simply
# means nothing in it is recognized as any protocol at all (every packet still decodes at the
# link layer, just with no application-layer match) -- confirms no accidental cross-link-type
# leakage either way.
add_test(NAME devicenet_protocol_filter_still_decodes_on_can_capture
  COMMAND conduitscope decode --protocol devicenet --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_protocol_filter_still_decodes_on_can_capture PROPERTIES
  PASS_REGULAR_EXPRESSION "#1  .*\\[devicenet\\]  DeviceNet Group 1")

add_test(NAME devicenet_protocol_filter_excludes_other_protocols_on_can_capture
  COMMAND conduitscope decode --protocol modbus --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --format text)
set_tests_properties(devicenet_protocol_filter_excludes_other_protocols_on_can_capture PROPERTIES
  PASS_REGULAR_EXPRESSION "#1  .*\\[non-ip\\]  CAN frame, id=0x305 \\(not decoded -- DeviceNet decoding disabled by --protocol\\)")

add_test(NAME devicenet_protocol_filter_does_not_affect_ethernet_capture
  COMMAND conduitscope decode --protocol devicenet --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_stp.pcap" --format text)
set_tests_properties(devicenet_protocol_filter_does_not_affect_ethernet_capture PROPERTIES
  FAIL_REGULAR_EXPRESSION "\\[devicenet\\]")

# Stats accumulation across the whole synthetic fixture.
add_test(NAME devicenet_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap" --stats)
set_tests_properties(devicenet_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "devicenet message groups:\n *Group 1 +7\n *Group 2 +6\n *Group 3 +9\n *Group 4 +6\n *Unclassified \\(0x07F0-0x07FF\\) +1\ndevicenet message types:.*devicenet fragmented group 3 messages: 1\ndevicenet can fd frames: 1")

# `info` reports the same devicenet message-type histogram --stats does, for a link-type-only
# protocol with no port at all (mirrors GOOSE's own `info` precedent).
add_test(NAME devicenet_info_reports_message_types
  COMMAND conduitscope info --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_devicenet.pcap")
set_tests_properties(devicenet_info_reports_message_types PROPERTIES
  PASS_REGULAR_EXPRESSION "link type: +Linux SocketCAN \\(DeviceNet\\).*devicenet message groups:\n *Group 1 +7\n *Group 2 +6\n *Group 3 +9\n *Group 4 +6")

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
# HART-IP (synthetic, tests/sample_hartip.pcap): 8-byte fixed header, Session
# Initiate/Close/Keep Alive/Pass-Through message bodies, the full per-command
# value-decode dispatch table, packed-ASCII and HART-timestamp decoding, and
# the documented, deliberately-unresolved TCP Session-Initiate-vs-Modbus/TCP
# detection collision. See tools/make_sample_pcap.py's build_hartip_sample
# for the exact byte layout each assertion below is checking (packet numbers
# in comments match that function's own numbered comments 1-63), and
# hartip.hpp's file header comment for the structural detection gate and the
# known collision's full explanation. JSON is pretty-printed one field per
# line, so assertions below join fields with ".*" (CMake's regex "." matches
# newlines) except where a field (e.g. hartip_values, notes) is itself a
# single-line JSON array.
# --------------------------------------------------------------------------

add_test(NAME hartip_session_initiate_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_session_initiate_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  Request Session Initiate host-type=Primary Host inactivity-close-timer=180s")

add_test(NAME hartip_session_initiate_response_json
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_session_initiate_response_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_message_type\": \"Response\",.*\"hartip_message_id\": \"Session Initiate\",.*\"hartip_host_type\": \"Secondary Host\",.*\"hartip_inactivity_close_timer\": 180,")

add_test(NAME hartip_keep_alive_request_and_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_keep_alive_request_and_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  Request Keep Alive\n.*\\[hartip\\]  Response Keep Alive")

add_test(NAME hartip_session_close_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_session_close_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  Request Session Close\n")

add_test(NAME hartip_error_known_code_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_error_known_code_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  Error Session Close error-code=0 \\(Session closed\\)")

add_test(NAME hartip_nak_known_code_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_nak_known_code_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  NAK Session Close error-code=2 \\(Service unavailable\\)")

add_test(NAME hartip_error_unknown_code_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_error_unknown_code_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  Error Session Close error-code=9 \\(unknown\\(9\\)\\)")

add_test(NAME hartip_error_nak_malformed_body_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_error_nak_malformed_body_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: Error/NAK body is 2 byte\\(s\\), expected exactly 1 -- not decoded: 0001")

add_test(NAME hartip_session_initiate_malformed_body_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_session_initiate_malformed_body_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: Session Initiate body is 3 byte\\(s\\), expected exactly 5 -- not decoded: 010203")

add_test(NAME hartip_session_close_malformed_body_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_session_close_malformed_body_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: Session Close body is 1 byte\\(s\\), expected 0 \\(empty\\) -- not decoded: aa")

add_test(NAME hartip_cmd0_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_cmd0_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  Request Pass Through STX command=0 \\(Read Unique Identifier\\)")

add_test(NAME hartip_cmd0_response_basic_form_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd0_response_basic_form_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 0,.*\"hartip_command_name\": \"Read Unique Identifier\",.*\"hartip_values\": \\[\"expansion-code=0xFE\", \"expanded-device-type=0x1234\", \"min-request-preambles=5\", \"universal-command-revision=7\", \"device-revision=1\", \"software-revision=3\", \"hardware-revision=12\", \"physical-signaling-code=2\", \"flags=0x80\", \"device-id=001122\"\\],.*Read Unique Identifier response is the 12-byte basic form")

add_test(NAME hartip_cmd11_response_extended_form_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd11_response_extended_form_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 11,.*\"hartip_command_name\": \"Read Unique Identifier\",.*\"min-response-preambles=5\", \"max-device-variables=24\", \"configuration-change-counter=7\", \"extended-device-status=0x00\", \"manufacturer-id=0x004B\", \"private-label-distributor-code=0x004B\", \"device-profile=1\"\\]")

add_test(NAME hartip_cmd21_response_long_address_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd21_response_long_address_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_is_long_address\": true,.*\"hartip_address\": \"82004b0001\",.*\"hartip_command\": 21,")

add_test(NAME hartip_cmd1_request_and_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd1_request_and_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 1,.*\"hartip_command_name\": \"Read Primary Variable\",.*\"notes\": \\[\\]\n *\\},.*\"hartip_values\": \\[\"pv-units=1\", \"pv=72.500000\"\\]")

add_test(NAME hartip_cmd2_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd2_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 2,.*\"hartip_command_name\": \"Read Loop Current and Percent of Range\",.*\"hartip_values\": \\[\"pv-loop-current-ma=12.500000\", \"pv-percent-range=65.625000\"\\]")

add_test(NAME hartip_cmd3_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd3_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 3,.*\"hartip_command_name\": \"Read Dynamic Variables and Loop Current\",.*\"hartip_values\": \\[\"pv-loop-current-ma=12.500000\", \"pv-units=1\", \"pv=72.500000\", \"sv-units=32\", \"sv=15.000000\", \"tv-units=33\", \"tv=25.000000\", \"qv-units=250\", \"qv=0.000000\"\\]")

add_test(NAME hartip_cmd6_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd6_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 6,.*\"hartip_command_name\": \"Write Polling Address\",.*\"hartip_values\": \\[\"poll-address=3\", \"loop-current-mode=0\"\\]")

add_test(NAME hartip_cmd7_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd7_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 7,.*\"hartip_command_name\": \"Read Loop Configuration\",.*\"hartip_values\": \\[\"poll-address=0\", \"loop-current-mode=1\"\\]")

add_test(NAME hartip_cmd8_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd8_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 8,.*\"hartip_command_name\": \"Read Dynamic Variable Classifications\",.*\"hartip_values\": \\[\"pv-classification=1\", \"sv-classification=2\", \"tv-classification=2\", \"qv-classification=3\"\\]")

add_test(NAME hartip_cmd9_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd9_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 9,.*\"hartip_command_name\": \"Read Device Variables with Status\",.*\"device-variable\\[0\\]-code=1\", \"device-variable\\[0\\]-classification=1\", \"device-variable\\[0\\]-units=1\", \"device-variable\\[0\\]-value=72.500000\", \"device-variable\\[0\\]-status=0x00\", \"device-variable\\[1\\]-code=2\".*\"timestamp=00:01:30.000\"\\]")

add_test(NAME hartip_cmd12_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd12_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 12,.*\"hartip_command_name\": \"Read Message\",.*\"hartip_values\": \\[\"message=PUMP 1 HIGH VIBRATION ALARM     \"\\]")

add_test(NAME hartip_cmd17_request_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd17_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 17,.*\"hartip_command_name\": \"Write Message\",.*\"hartip_values\": \\[\"message=CALIBRATED 2026                 \"\\]")

add_test(NAME hartip_cmd13_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd13_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 13,.*\"hartip_command_name\": \"Read Tag, Descriptor, Date\",.*\"hartip_values\": \\[\"tag=PT-101  \", \"descriptor=PUMP DISCH PRESS\", \"date=03/15/2026\"\\]")

add_test(NAME hartip_cmd18_request_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd18_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 18,.*\"hartip_command_name\": \"Write Tag, Descriptor, Date\",.*\"hartip_values\": \\[\"tag=PT-101  \", \"descriptor=PUMP DISCH PRESS\", \"date=03/15/2026\"\\]")

add_test(NAME hartip_cmd14_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd14_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 14,.*\"hartip_command_name\": \"Read Primary Variable Transducer Information\",.*\"hartip_values\": \\[\"transducer-serial-number=010203\", \"limit-units=1\", \"upper-transducer-limit=500.000000\", \"lower-transducer-limit=-500.000000\", \"minimum-span=1.000000\"\\]")

add_test(NAME hartip_cmd15_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd15_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 15,.*\"hartip_command_name\": \"Read Device Information\",.*\"pv-alarm-selection=0\", \"pv-transfer-function=0\", \"range-units=1\", \"upper-range-value=500.000000\", \"lower-range-value=0.000000\", \"damping-value=0.500000\", \"write-protect=0\", \"reserved=0x00\", \"pv-analog-channel-flags=0x00\"\\]")

add_test(NAME hartip_cmd16_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd16_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 16,.*\"hartip_command_name\": \"Read Final Assembly Number\",.*\"hartip_values\": \\[\"final-assembly-number=12345\"\\]")

add_test(NAME hartip_cmd19_request_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd19_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 19,.*\"hartip_command_name\": \"Write Final Assembly Number\",.*\"hartip_values\": \\[\"final-assembly-number=12345\"\\]")

add_test(NAME hartip_cmd20_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd20_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 20,.*\"hartip_command_name\": \"Read Long Tag\",.*\"hartip_values\": \\[\"long-tag=PUMP-101-DISCHARGE-PRESSURE     \"\\]")

add_test(NAME hartip_cmd22_request_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd22_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 22,.*\"hartip_command_name\": \"Write Long Tag\",.*\"hartip_values\": \\[\"long-tag=PUMP-101-DISCHARGE-PRESSURE     \"\\]")

add_test(NAME hartip_cmd31_dispatches_to_203_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd31_dispatches_to_203_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 31,.*\"hartip_response_code\": 0,.*\"hartip_values\": \\[\"extended-command-number=64386\", \"index-of-first-discrete-variable=0\", \"number-of-discrete-variables=2\", \"extended-device-status=0x00\", \"timestamp=00:00:05.000\", \"discrete-variable\\[0\\]-state=1\", \"discrete-variable\\[0\\]-status=0x00\", \"discrete-variable\\[1\\]-state=0\", \"discrete-variable\\[1\\]-status=0x00\"\\]")

add_test(NAME hartip_cmd31_non_64386_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd31_non_64386_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 31,.*\"hartip_response_code\": 0,.*\"hartip_response_is_comm_error\": false,.*\"hartip_response_code_name\": \"Success\",.*\"hartip_device_status\": 0,.*\"hartip_values\": \\[\"extended-command-number=1000\"\\]")

add_test(NAME hartip_cmd203_standalone_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd203_standalone_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 203,.*\"hartip_response_code\": 0,.*\"hartip_values\": \\[\"index-of-first-discrete-variable=0\", \"number-of-discrete-variables=2\", \"extended-device-status=0x00\", \"timestamp=00:00:05.000\", \"discrete-variable\\[0\\]-state=1\", \"discrete-variable\\[0\\]-status=0x00\", \"discrete-variable\\[1\\]-state=0\", \"discrete-variable\\[1\\]-status=0x00\"\\]")

add_test(NAME hartip_cmd33_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd33_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 33,.*\"hartip_command_name\": \"Read Device Variables\",.*\"device-variable\\[0\\]-code=1\", \"device-variable\\[0\\]-units=1\", \"device-variable\\[0\\]-value=72.500000\", \"device-variable\\[1\\]-code=2\", \"device-variable\\[1\\]-units=32\", \"device-variable\\[1\\]-value=15.000000\"\\]")

add_test(NAME hartip_cmd38_request_and_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd38_request_and_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 38,.*\"hartip_command_name\": \"Reset Configuration Changed Flag\",.*\"notes\": \\[\\]\n *\\},.*\"hartip_command\": 38,.*\"hartip_command_name\": \"Reset Configuration Changed Flag\",.*\"hartip_response_code\": 0,.*\"hartip_values\": \\[\"configuration-change-counter=42\"\\]")

add_test(NAME hartip_cmd48_minimal_and_extended_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd48_minimal_and_extended_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 48,.*\"hartip_command_name\": \"Read Additional Device Status\",.*\"hartip_values\": \\[\"device-specific-status=000000000000\"\\],.*\"notes\": \\[\\]\n *\\},.*\"device-specific-status=000000000000\", \"extended-device-status=0x00\", \"device-operating-mode=0x01\", \"standardized-status-0=0x00\", \"standardized-status-1=0x00\", \"standardized-status-2=0x00\", \"standardized-status-3=0x00\", \"analog-channel-saturated=0x00\", \"analog-channel-fixed=0x00\"\\]")

add_test(NAME hartip_cmd77_response_short_address_embedded_command_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd77_response_short_address_embedded_command_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 77,.*\"hartip_command_name\": \"Send Command to Sub-Device\",.*\"hartip_values\": \\[\"io-card=3\", \"channel=1\", \"embedded-command-delimiter=0x00\", \"embedded-address=7\", \"embedded-command=1\", \"embedded-response-code=0 \\(Success\\)\", \"embedded-device-status=0x00\", \"embedded-command-name=Read Primary Variable\", \"embedded-pv-units=1\", \"embedded-pv=72.500000\"\\],.*\"notes\": \\[\\]")

add_test(NAME hartip_cmd77_response_long_address_embedded_command_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd77_response_long_address_embedded_command_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 77,.*\"hartip_values\": \\[\"io-card=3\", \"channel=1\", \"embedded-command-delimiter=0x80\", \"embedded-address=1eaabbccdd\", \"embedded-command=1\", \"embedded-response-code=0 \\(Success\\)\", \"embedded-device-status=0x00\", \"embedded-command-name=Read Primary Variable\", \"embedded-pv-units=1\", \"embedded-pv=72.500000\"\\]")

add_test(NAME hartip_cmd77_request_embedded_command_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd77_request_embedded_command_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_message_type\": \"Request\",.*\"hartip_command\": 77,.*\"hartip_command_name\": \"Send Command to Sub-Device\",.*\"hartip_values\": \\[\"io-card=3\", \"channel=1\", \"tx-preamble-count=2\", \"embedded-command-delimiter=0x00\", \"embedded-address=7\", \"embedded-command=1\"\\]")

add_test(NAME hartip_cmd77_truncated_before_embedded_command_number_noted
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd77_truncated_before_embedded_command_number_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 77,.*\"hartip_values\": \\[\"io-card=1\", \"channel=0\", \"embedded-command-delimiter=0x00\", \"embedded-address=5\"\\],.*\"notes\": \\[\"command 77 is truncated before its Embedded Command Number byte\"\\]")

add_test(NAME hartip_cmd178_aggregate_recognized_and_unrecognized_entries_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd178_aggregate_recognized_and_unrecognized_entries_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 178,.*\"hartip_values\": \\[\"number-of-commands=2\", \"aggregate\\[0\\]-command=1\", \"aggregate\\[0\\]-response-code=0 \\(Success\\)\", \"aggregate\\[0\\]-command-name=Read Primary Variable\", \"aggregate\\[0\\]-pv-units=1\", \"aggregate\\[0\\]-pv=72.500000\", \"aggregate\\[1\\]-command=99\", \"aggregate\\[1\\]-response-code=0 \\(Success\\)\", \"aggregate\\[1\\]-data=aabb\"\\],.*\"notes\": \\[\"command 178 entry 1: command 99 is not one of this decoder's first-pass value-decoded commands -- not decoded, shown as raw hex\"\\]")

add_test(NAME hartip_cmd178_entry_byte_count_too_small_noted
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_cmd178_entry_byte_count_too_small_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_command\": 178,.*\"hartip_values\": \\[\"number-of-commands=2\", \"aggregate\\[0\\]-command=1\"\\],.*\"notes\": \\[\"command 178 entry 0's Command Byte Count \\(0\\) is smaller than the 1 Response Code byte it must include -- entry's Response Code/Data not decoded, remaining entries \\(if any\\) skipped\"\\]")

add_test(NAME hartip_cmd99_unrecognized_raw_hex_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_cmd99_unrecognized_raw_hex_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "command=99 response-code=0 \\(Success\\)\n *note: command 99 is not one of this decoder's first-pass value-decoded commands -- not decoded, shown as raw hex")

add_test(NAME hartip_wrong_length_recognized_command_raw_hex_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_wrong_length_recognized_command_raw_hex_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "command=1 \\(Read Primary Variable\\) response-code=0 \\(Success\\)\n *note: command 1 \\(Read Primary Variable\\) data \\(4 byte\\(s\\)\\) does not match the byte layout this decoder expects -- not value-decoded, shown as raw hex")

add_test(NAME hartip_comm_error_response_code_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_comm_error_response_code_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_response_code\": 200,.*\"hartip_response_is_comm_error\": true,.*\"hartip_comm_error_flags\": \\[\"vertical-parity-error\", \"longitudinal-parity-error\"\\],")

add_test(NAME hartip_single_definition_response_code_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_single_definition_response_code_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "response-code=32 \\(Busy\\)")

add_test(NAME hartip_unlisted_response_code_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_unlisted_response_code_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "response-code=100 \\(command-specific response code 100 \\(meaning depends on which command produced it -- not decoded\\)\\)")

add_test(NAME hartip_all_device_status_flags_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_all_device_status_flags_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_device_status\": 255,.*\"hartip_device_status_flags\": \\[\"field-device-malfunction\", \"configuration-changed\", \"cold-start\", \"more-status-available\", \"loop-current-fixed\", \"loop-current-saturated\", \"non-primary-variable-out-of-limits\", \"primary-variable-out-of-limits\"\\],")

add_test(NAME hartip_back_frame_type_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_back_frame_type_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  Response Pass Through BACK command=2 \\(Read Loop Current and Percent of Range\\)")

add_test(NAME hartip_byte_count_too_small_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_byte_count_too_small_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: Pass-Through Byte Count \\(1\\) is smaller than the 2 Response Code/Device Status byte\\(s\\) it must include -- Data length treated as 0")

add_test(NAME hartip_truncated_before_checksum_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_truncated_before_checksum_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: Pass-Through body truncated before its trailing Checksum byte")

add_test(NAME hartip_truncated_before_command_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_truncated_before_command_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  Request Pass Through STX command=0\n *note: Pass-Through body truncated before its Command byte")

add_test(NAME hartip_trailing_bytes_after_checksum_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_trailing_bytes_after_checksum_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: 2 trailing byte\\(s\\) remain after the Checksum -- unexpected, not decoded")

add_test(NAME hartip_non_standard_udp_port_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_non_standard_udp_port_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50:51005 -> 192.168.1.10:51006  \\[hartip\\]  Request Keep Alive\n *note: seen on UDP port 51005->51006, which is not a configured/standard HART-IP port \\(5094\\)")

add_test(NAME hartip_msg_length_implausible_falls_back_to_udp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_msg_length_implausible_falls_back_to_udp PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 13 byte\\(s\\) on port 5094->5094")

add_test(NAME hartip_invalid_message_type_falls_back_to_udp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_invalid_message_type_falls_back_to_udp PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 8 byte\\(s\\) on port 5094->5094")

# The documented, deliberately-unresolved limitation: a HART-IP Session Initiate message's own
# header (MessageID 0, Status 0) reads as a plausible Modbus/TCP MBAP header, so on TCP it is
# misclassified as Modbus/TCP "buffering, waiting for more" bytes that never arrive -- see
# hartip.hpp's "KNOWN, ACCEPTED, DOCUMENTED LIMITATION" paragraph and decoder.cpp's matching
# comments on both the declared-length chain and the TCP dispatch chain for the full explanation
# and why reordering HART-IP ahead of Modbus was tried and rejected (it regressed this project's
# own Modbus/S7comm test corpus). These three packets (a genuine Session Initiate request,
# response, and the start of a coalesced Keep Alive) are never decoded as hartip on this flow.
add_test(NAME hartip_modbus_collision_known_limitation
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_modbus_collision_known_limitation PROPERTIES
  PASS_REGULAR_EXPRESSION "52010->5094: 13 of 106 declared byte\\(s\\) seen so far across 1 segment\\(s\\) on this flow, waiting for more\n.*5094->52010: 13 of 106 declared byte\\(s\\) seen so far across 1 segment\\(s\\) on this flow, waiting for more\n.*52010->5094: 29 of 106 declared byte\\(s\\) seen so far across 2 segment\\(s\\) on this flow, waiting for more")

add_test(NAME hartip_modbus_collision_never_reports_hartip_protocol
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap")
set_tests_properties(hartip_modbus_collision_never_reports_hartip_protocol PROPERTIES
  PASS_REGULAR_EXPRESSION "\"src_port\": 52010,\n *\"dst_port\": 5094,\n *\"tcp_flags\": \"ACK,PSH\",\n *\"protocol\": \"tcp\",")

add_test(NAME hartip_tcp_pass_through_non_standard_port_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_tcp_pass_through_non_standard_port_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50:52099 -> 192.168.1.10:15094  \\[hartip\\]  Request Pass Through STX command=1 \\(Read Primary Variable\\)\n *note: seen on TCP port 52099->15094, which is not a configured/standard HART-IP port \\(5094\\)\n.*192.168.1.10:15094 -> 192.168.1.50:52099  \\[hartip\\]  Response Pass Through ACK command=1 \\(Read Primary Variable\\) response-code=0 \\(Success\\) \\[pv-units=1 \\+1 more\\]\n *note: seen on TCP port 15094->52099, which is not a configured/standard HART-IP port \\(5094\\)")

add_test(NAME hartip_tcp_coalesced_keep_alive_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --format text)
set_tests_properties(hartip_tcp_coalesced_keep_alive_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50:52150 -> 192.168.1.10:5094 \\(hart-ip\\)  \\[hartip\\]  Request Keep Alive\n *note: additional HART-IP message 2 found in the same TCP payload at byte offset 8 \\(coalesced by the sender/OS\\): Request Keep Alive")

add_test(NAME hartip_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --stats)
set_tests_properties(hartip_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +67[^\n]*\n[^\n]*\nprotocols:\n *hartip +62\n *tcp +3\n *udp +2\nhartip message types:\n *Error +3\n *NAK +1\n *Request +17\n *Response +41\nhartip pass-through commands:\n")

# --------------------------------------------------------------------------
# Real-world HART-IP capture -- see tests/real_captures/hartip/ATTRIBUTION.md for provenance: a
# genuine 116-frame, 72-second capture (automayt/ICS-pcap, fetched via GitHub's LFS media CDN)
# of a WirelessHART gateway ("wihartgw") running the same command sequence over both UDP and TCP.
# Independently cross-validated against tshark's own HART-IP dissector (see ATTRIBUTION.md) and,
# notably, this capture reproduces the documented TCP Modbus-collision limitation on genuine field
# traffic, plus a second, previously-undocumented weak-gate false-positive pattern against
# unrelated background TCP traffic -- see ATTRIBUTION.md's own two dedicated sections for both.
# --------------------------------------------------------------------------

add_test(NAME real_hartip_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng" --format json)

add_test(NAME real_hartip_stats_summary
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng" --stats)
set_tests_properties(real_hartip_stats_summary PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +116[^\n]*\n[^\n]*\nprotocols:\n *hartip +46\n *modbus +2\n *non-ip +4\n *non-tcp +1\n *tcp +63\n.*hartip message types:\n *Request +23\n *Response +23\nhartip pass-through commands:\n")

add_test(NAME real_hartip_command_coverage_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng" --stats)
set_tests_properties(real_hartip_command_coverage_json PROPERTIES
  PASS_REGULAR_EXPRESSION "0 \\(Read Unique Identifier\\) +4\n *1 \\(Read Primary Variable\\) +4\n *12 \\(Read Message\\) +4\n *13 \\(Read Tag, Descriptor, Date\\) +4\n *2 \\(Read Loop Current and Percent of Range\\) +4\n *20 \\(Read Long Tag\\) +4\n *3 \\(Read Dynamic Variables and Loop Current\\) +4\n *48 \\(Read Additional Device Status\\) +4\n *9 \\(Read Device Variables with Status\\) +4")

add_test(NAME real_hartip_session_initiate_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng" --format text)
set_tests_properties(real_hartip_session_initiate_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hartip\\]  Request Session Initiate host-type=Primary Host inactivity-close-timer=30000s")

# A real device sent IEEE-754 NaN bytes for PV Loop Current -- tshark's own HART-IP dissector
# decodes the identical real bytes the same way (see ATTRIBUTION.md); not a decoder bug.
add_test(NAME real_hartip_nan_loop_current_matches_wireshark
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng" --format text)
set_tests_properties(real_hartip_nan_loop_current_matches_wireshark PROPERTIES
  PASS_REGULAR_EXPRESSION "command=2 \\(Read Loop Current and Percent of Range\\) response-code=0 \\(Success\\) \\[pv-loop-current-ma=nan \\+1 more\\]")

# Packed-ASCII decode of a real device's Message field -- cross-checked byte-for-byte against
# tshark's own dissector output (see ATTRIBUTION.md); genuine lab/demo placeholder text, not a bug.
add_test(NAME real_hartip_packed_ascii_message_matches_wireshark
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng" --format text)
set_tests_properties(real_hartip_packed_ascii_message_matches_wireshark PROPERTIES
  PASS_REGULAR_EXPRESSION "command=12 \\(Read Message\\) response-code=0 \\(Success\\) \\[message=@ABCDEFGHIJKLMNO/ !-#\\$%&'\\(\\)\\*\\+,-\\.\\]")

# Command 0 (Read Unique Identifier) is genuinely addressed to the universal short address 0 --
# the real device's own long address (264e0000d2) is only used starting with the next command,
# exactly the standard HART discover-then-address pattern this decoder's hartip_is_long_address/
# hartip_address fields are meant to capture.
add_test(NAME real_hartip_short_address_universal_poll_for_unique_id
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng")
set_tests_properties(real_hartip_short_address_universal_poll_for_unique_id PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_is_long_address\": false,.*\"hartip_address\": \"00\",.*\"hartip_command\": 0,.*\"hartip_command_name\": \"Read Unique Identifier\",")

add_test(NAME real_hartip_long_address_used_for_later_commands
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng")
set_tests_properties(real_hartip_long_address_used_for_later_commands PROPERTIES
  PASS_REGULAR_EXPRESSION "\"hartip_is_long_address\": true,.*\"hartip_address\": \"264e0000d2\",.*\"hartip_command\": 20,.*\"hartip_command_name\": \"Read Long Tag\",.*\"long-tag=wihartgw")

# The documented TCP Session-Initiate-vs-Modbus/TCP collision (see hartip.hpp's "KNOWN, ACCEPTED,
# DOCUMENTED LIMITATION" paragraph, decoder.cpp's matching comments, and tests/sample_hartip.pcap's
# own packets 58-60) reproduced on genuine field traffic: this real TCP session's own Session
# Initiate request and response both get misclassified as Modbus/TCP, exactly as documented.
add_test(NAME real_hartip_modbus_collision_confirmed_on_real_traffic
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng" --format text)
set_tests_properties(real_hartip_modbus_collision_confirmed_on_real_traffic PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.0.101:49559 -> 192.168.0.10:5094 \\(hart-ip\\)  \\[modbus\\]  Unknown \\(0xd\\): Unknown \\(0xd\\)[^\n]*\n.*192.168.0.10:5094 \\(hart-ip\\) -> 192.168.0.101:49559  \\[modbus\\]  Unknown \\(0xd\\): Unknown \\(0xd\\)")

# New (see ATTRIBUTION.md): the weak declared-length gate also false-positives against unrelated
# background TCP traffic having nothing to do with HART-IP (a TLS connection and an SMB
# connection elsewhere in this same capture) -- real-world confirmation, beyond the Modbus
# collision above, that hartip.hpp's own "structural detection gate is genuinely weak" paragraph
# is not overstated.
add_test(NAME real_hartip_weak_gate_false_positive_on_unrelated_tcp_traffic
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/hartip/hart_ip.pcapng" --format text)
set_tests_properties(real_hartip_weak_gate_false_positive_on_unrelated_tcp_traffic PROPERTIES
  PASS_REGULAR_EXPRESSION "50322->443: 27 of 54734 declared byte\\(s\\) seen so far.*49343->445: 44 of 19778 declared byte\\(s\\) seen so far")

# --------------------------------------------------------------------------
# OPC UA Binary (synthetic, tests/sample_opcua.pcap): the UA-TCP connection-protocol handshake
# (Hello/Acknowledge/Error/ReverseHello), a full OpenSecureChannel/CloseSecureChannel round trip
# with SecurityPolicyUri "...#None", the GetEndpoints/FindServers discovery services, a
# CreateSession/ActivateSession/CloseSession lifecycle (including both an Anonymous and a
# cleartext-UserName/Password ActivateSession -- the latter deliberately exercising the
# "SECURITY FINDING" credential-exposure note), a Tier-2 (header-decoded, body-raw-hex) Read
# request/response pair, an entirely unrecognized service TypeId, a non-'F' chunk, a
# structurally-invalid NodeId shape (the inner try/catch regression case), a genuinely truncated
# capture (TCP-reassembly "buffering, waiting for more" path), port-independence, and coalesced
# messages. See tools/make_sample_pcap.py's build_opcua_sample docstring for the full packet-by-
# packet rationale, and opcua.hpp's file header comment for the wire format each packet below
# exercises (cross-checked against the OPC Foundation's own Part4/Part6 reference documentation,
# its own published NodeIds.csv/StatusCode.csv, and python-opcua's own generated bindings -- see
# opcua.hpp's own "Sourcing" paragraph). Like every other synthetic fixture's own test block in
# this file, JSON field assertions below join adjacent fields with ".*" rather than a literal
# ", " -- this project's pretty-printed JSON puts one field per line, and CMake's own regex engine
# lets "." match newlines, so a literal ", " would never match across a line break.
# --------------------------------------------------------------------------

add_test(NAME opcua_hello_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_hello_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[opcua\\]  Hello protocol-version=0 receive-buffer-size=65536 send-buffer-size=65536 max-message-size=0 max-chunk-count=0 endpoint-url=opc.tcp://192.168.1.10:4840/UA/PLC")

add_test(NAME opcua_acknowledge_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_acknowledge_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[opcua\\]  Acknowledge protocol-version=0 receive-buffer-size=65536 send-buffer-size=65536 max-message-size=0 max-chunk-count=0")

add_test(NAME opcua_open_secure_channel_request_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_open_secure_channel_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_message_type\": \"OpenSecureChannel\",.*\"opcua_secure_channel_id\": 0,.*\"opcua_is_asymmetric\": true,.*\"opcua_security_policy_uri\": \"http://opcfoundation.org/UA/SecurityPolicy#None\",.*\"opcua_service_name\": \"OpenSecureChannelRequest\",.*\"opcua_service_type_id\": 446,.*\"opcua_values\": \\[.*\"request-type=Issue\", \"security-mode=None\", \"client-nonce-length=0\", \"requested-lifetime-ms=3600000\"\\],")

add_test(NAME opcua_open_secure_channel_response_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_open_secure_channel_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"OpenSecureChannelResponse\",.*\"opcua_service_type_id\": 449,.*\"opcua_status_code_name\": \"Good\",.*\"opcua_status_is_good\": true,.*\"security-token-channel-id=500001\", \"security-token-id=1\", \"security-token-created-at=2023-11-14T23:53:21.000Z\", \"revised-lifetime-ms=3600000\", \"server-nonce-length=4\"\\],")

add_test(NAME opcua_get_endpoints_response_endpoint_array_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_get_endpoints_response_endpoint_array_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"GetEndpointsResponse\",.*\"endpoint-count=2\", \"endpoint\\[0\\]=opc.tcp://192.168.1.10:4840/UA/PLC \\(security=None, policy=http://opcfoundation.org/UA/SecurityPolicy#None\\)\", \"endpoint\\[1\\]=opc.tcp://192.168.1.10:4840/UA/PLC \\(security=SignAndEncrypt, policy=http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256\\)\"\\],")

add_test(NAME opcua_find_servers_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_find_servers_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[opcua\\]  Message channel=500001 token=1 FindServersResponse result=Good")

add_test(NAME opcua_create_session_request_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_create_session_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"CreateSessionRequest\",.*\"client-application-uri=urn:conduitscope:sample-hmi\", \"endpoint-url=opc.tcp://192.168.1.10:4840/UA/PLC\", \"session-name=ConduitScope Sample Session\", \"requested-session-timeout-ms=1200000.000000\", \"max-response-message-size=0\"\\],")

add_test(NAME opcua_create_session_response_session_id_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_create_session_response_session_id_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"CreateSessionResponse\",.*\"session-id=ns=1;i=1001\", \"revised-session-timeout-ms=1200000.000000\", \"server-endpoint-count=0\", \"max-request-message-size=0\"\\],")

add_test(NAME opcua_activate_session_anonymous_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_activate_session_anonymous_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"ActivateSessionRequest\",.*\"opcua_values\": \\[.*\"identity=anonymous \\(policy-id=anonymous\\)\"\\],.*\"notes\": \\[\\]")

add_test(NAME opcua_activate_session_username_password_cleartext_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_activate_session_username_password_cleartext_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"identity=username \\(policy-id=username_basic256\\)\", \"username=operator1\", \"password=Sup3rSecret!1\"\\],.*\"notes\": \\[\"SECURITY FINDING: UserNameIdentityToken's own EncryptionAlgorithm field is empty, meaning the password above was placed on the wire UNENCRYPTED")

add_test(NAME opcua_read_request_nodes_to_read_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_read_request_nodes_to_read_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"ReadRequest\",.*\"opcua_values\": \\[.*\"max-age-ms=5000.000000\", \"timestamps-to-return=Both\", \"nodes-to-read-count=1\", \"nodes-to-read\\[0\\]=ns=2;i=1001 attribute=Value\"\\],.*\"opcua_body_shown_as_hex\": false,")

add_test(NAME opcua_read_response_datavalue_all_six_fields_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_read_response_datavalue_all_six_fields_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"ReadResponse\",.*\"opcua_values\": \\[.*\"results-count=1\", \"results\\[0\\]=\\{value=\\(Int32\\) 42, status=Good, source-timestamp=2023-11-14T23:53:20.000Z, source-picoseconds=500, server-timestamp=2023-11-14T23:53:21.000Z, server-picoseconds=250\\}\"\\],")

add_test(NAME opcua_write_request_float_value_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_write_request_float_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"WriteRequest\",.*\"nodes-to-write-count=1\", \"nodes-to-write\\[0\\]=ns=2;i=1002 attribute=Value value=\\{value=\\(Float\\) 3.500000\\}\"\\],")

add_test(NAME opcua_write_response_good_status_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_write_response_good_status_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[opcua\\]  Message channel=500001 token=1 WriteResponse result=Good")

add_test(NAME opcua_call_request_input_string_array_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_call_request_input_string_array_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"CallRequest\",.*\"call\\[0\\]=object=ns=2;i=2000 method=ns=2;i=2001 input-arguments=\\[\\(String\\[3\\]\\) a, bee, c\\]\"\\],")

add_test(NAME opcua_call_response_output_uint32_array_with_dims_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_call_response_output_uint32_array_with_dims_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"CallResponse\",.*\"result\\[0\\]=status=Good output-arguments=\\[\\(UInt32\\[2\\]\\) 10, 20 dims=\\[2\\]\\]\"\\],")

add_test(NAME opcua_write_request_null_variant_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_write_request_null_variant_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"WriteRequest\",.*\"nodes-to-write\\[0\\]=ns=2;i=1003 attribute=Value value=\\{value=\\(Null\\)\\}\"\\],")

add_test(NAME opcua_unrecognized_service_typeid_shown_as_hex
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_unrecognized_service_typeid_shown_as_hex PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"Message channel=500001 token=1 \\(service type-id 999999, ns=0 -- not in this decoder's dispatch table\\)\",.*\"opcua_service_recognized\": false,.*\"opcua_service_type_id\": 999999,.*\"opcua_has_header\": false,.*\"opcua_body_shown_as_hex\": true,.*\"opcua_body_hex\": \"de ad be ef 00 01\",")

add_test(NAME opcua_close_session_decoded
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_close_session_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"CloseSessionRequest\",.*\"opcua_values\": \\[\"timestamp=2023-11-14T23:53:20.000Z\", \"request-handle=11\", \"delete-subscriptions=true\"\\],")

add_test(NAME opcua_close_secure_channel_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_close_secure_channel_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[opcua\\]  CloseSecureChannel channel=500001 token=1 CloseSecureChannelRequest")

add_test(NAME opcua_error_message_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_error_message_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[opcua\\]  Error error=BadSecureChannelIdInvalid reason=SecureChannel has been closed")

add_test(NAME opcua_reverse_hello_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_reverse_hello_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.10:4840 \\(opcua\\) -> 192.168.1.50:53100  \\[opcua\\]  ReverseHello server-uri=urn:conduitscope:sample-plc endpoint-url=opc.tcp://192.168.1.10:4840/UA/PLC")

add_test(NAME opcua_intermediate_chunk_not_reassembled_noted
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_intermediate_chunk_not_reassembled_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_chunk_type\": \"C\",.*\"opcua_secure_channel_id\": 424242,.*\"opcua_token_id\": 7,.*\"opcua_body_shown_as_hex\": true,.*\"opcua_body_hex\": \"01 02 03 04 05 06 07 08\",.*\"notes\": \\[\"chunk type 'C' -- this decoder does not reassemble a message split across multiple OPC UA chunks")

add_test(NAME opcua_invalid_nodeid_shape_falls_back_to_hex_preserving_channel_fields
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap")
set_tests_properties(opcua_invalid_nodeid_shape_falls_back_to_hex_preserving_channel_fields PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_secure_channel_id\": 555555,.*\"opcua_token_id\": 9,.*\"opcua_service_recognized\": false,.*\"opcua_has_header\": false,.*\"opcua_body_shown_as_hex\": true,.*\"opcua_body_hex\": \"3f aa bb cc\",")

add_test(NAME opcua_truncated_capture_buffers_waiting_for_more
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_truncated_capture_buffers_waiting_for_more PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[tcp\\]  buffering a OPC UA message PDU/frame split across TCP segments 53202->4840: 66 of 166 declared byte\\(s\\) seen so far across 1 segment\\(s\\) on this flow, waiting for more")

add_test(NAME opcua_non_standard_port_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_non_standard_port_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50:53210 -> 192.168.1.10:51005  \\[opcua\\]  Hello.*\n *note: seen on TCP port 53210->51005, which is not a configured/standard OPC UA port \\(4840\\)")

add_test(NAME opcua_coalesced_messages_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text)
set_tests_properties(opcua_coalesced_messages_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50:53220 -> 192.168.1.10:4840 \\(opcua\\)  \\[opcua\\]  Hello.*\n *note: additional OPC UA message 2 found in the same TCP payload at byte offset 66 \\(coalesced by the sender/OS\\): Acknowledge")

add_test(NAME opcua_extra_port_option_suppresses_unexpected_port_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --format text --opcua-port 51005)
set_tests_properties(opcua_extra_port_option_suppresses_unexpected_port_note PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50:53210 -> 192.168.1.10:51005  \\[opcua\\]  Hello"
  FAIL_REGULAR_EXPRESSION "not a configured/standard OPC UA port")

add_test(NAME opcua_protocol_filter_excludes_other_protocols
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --protocol opcua --format text)
set_tests_properties(opcua_protocol_filter_excludes_other_protocols PROPERTIES
  FAIL_REGULAR_EXPRESSION "\\[modbus\\]")

add_test(NAME opcua_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --stats)
set_tests_properties(opcua_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +33[^\n]*\n[^\n]*\nprotocols:\n *opcua +32\n *tcp +1\nopcua message types:\n *Acknowledge +1\n *CloseSecureChannel +1\n *Error +1\n *Hello +3\n *Message +23\n *OpenSecureChannel +2\n *ReverseHello +1\nopcua services:\n *ActivateSessionRequest +2\n *ActivateSessionResponse +2\n *CallRequest +1\n *CallResponse +1\n")

# --------------------------------------------------------------------------
# Real-world OPC UA capture -- see tests/real_captures/opcua/ATTRIBUTION.md for provenance: two
# back-to-back OPC UA Binary (UA-TCP/Secure Conversation) sessions from Wireshark Bug 3986's own
# attachment (a 2009 dissector-freeze reproduction capture, an OPC UA conformance/fuzz-test tool
# -- Achilles Satellite -- against a reference "StackTestServer" implementation). Independently
# cross-validated against tshark's own OPC UA dissector (which needs an explicit "Decode As", since
# this capture uses non-standard TCP port 12001, not 4840 -- see ATTRIBUTION.md's own
# "Port-independent detection confirmed on real traffic" section for why that itself is a
# meaningful real-world result for this decoder's own port-independent detection gate).
# --------------------------------------------------------------------------

add_test(NAME real_opcua_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap" --format json)

add_test(NAME real_opcua_stats_summary
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap" --stats)
set_tests_properties(real_opcua_stats_summary PROPERTIES
  # Both sessions' CallRequest (TypeId 712) no longer appear under "opcua services" now that Call is
  # Tier 1: their own bodies are genuinely malformed (Achilles Satellite fuzz-test payloads -- see
  # ATTRIBUTION.md -- e.g. session 1's carries a method-id NodeId claiming a 262144-byte String with
  # only ~21 bytes actually left in the captured body), so decode_call_request_params's own bounds-
  # checked reads now correctly throw and this decoder honestly falls back to "not in this decoder's
  # dispatch table" for them, rather than the old Tier-2 behavior of labeling them "CallRequest"
  # without ever having attempted to parse their bodies at all -- see the tests below this one.
  PASS_REGULAR_EXPRESSION "packets: +90[^\n]*\n[^\n]*\nprotocols:\n *opcua +24\n *tcp +66\nopcua message types:\n *Acknowledge +2\n *Error +2\n *Hello +2\n *Message +14\n *OpenSecureChannel +4\nopcua services:\n *ActivateSessionRequest +2\n *ActivateSessionResponse +2\n *CreateSessionRequest +2\n *CreateSessionResponse +2\n *GetEndpointsRequest +2\n *GetEndpointsResponse +2\n *OpenSecureChannelRequest +2\n *OpenSecureChannelResponse +2")

add_test(NAME real_opcua_port_independent_detection_on_nonstandard_port
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap" --format text)
set_tests_properties(real_opcua_port_independent_detection_on_nonstandard_port PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.41.176:58674 -> 192.168.41.212:12001  \\[opcua\\]  Hello protocol-version=0 receive-buffer-size=65535 send-buffer-size=65535 max-message-size=4000 max-chunk-count=0 endpoint-url=opc.tcp://vm-xp-steven:12001/UA/StackTestServer\n *note: seen on TCP port 58674->12001, which is not a configured/standard OPC UA port \\(4840\\)")

add_test(NAME real_opcua_get_endpoints_response_five_endpoints_matches_wireshark
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap")
set_tests_properties(real_opcua_get_endpoints_response_five_endpoints_matches_wireshark PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"GetEndpointsResponse\",.*\"opcua_service_type_id\": 431,.*\"endpoint-count=5\", \"endpoint\\[0\\]=opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048 \\(security=None, policy=http://opcfoundation.org/UA/SecurityPolicy#None\\)\".*\"endpoint\\[4\\]=opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048 \\(security=Sign, policy=http://opcfoundation.org/UA/SecurityPolicy#Basic256\\)\"\\],")

add_test(NAME real_opcua_get_endpoints_response_reassembled_across_5_segments
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap")
set_tests_properties(real_opcua_get_endpoints_response_reassembled_across_5_segments PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"GetEndpointsResponse\",.*\"opcua_message_size\": 7008,")

add_test(NAME real_opcua_create_session_response_matches_wireshark_session_id
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap")
set_tests_properties(real_opcua_create_session_response_matches_wireshark_session_id PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"CreateSessionResponse\",.*\"opcua_message_size\": 8086,.*\"session-id=ns=10;i=365457\",")

add_test(NAME real_opcua_activate_session_anonymous_real_client
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap")
set_tests_properties(real_opcua_activate_session_anonymous_real_client PROPERTIES
  PASS_REGULAR_EXPRESSION "\"opcua_service_name\": \"ActivateSessionRequest\",.*\"identity=anonymous \\(policy-id=0\\)\"\\],")

add_test(NAME real_opcua_call_request_first_session_body_rejected_as_malformed
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap")
set_tests_properties(real_opcua_call_request_first_session_body_rejected_as_malformed PROPERTIES
  # This session's CallRequest (TypeId 712, reassembled from 4 TCP segments) is one of the Achilles
  # Satellite fuzz-test payloads this capture is built from (see ATTRIBUTION.md): its CallMethodRequest
  # array's own MethodId NodeId claims a String identifier 262144 bytes long with only ~21 bytes
  # actually present in the captured body. Now that Call is Tier 1, decode_call_request_params's
  # bounds-checked read_string throws, and this decoder correctly falls back to raw hex rather than
  # asserting a "CallRequest" label it was never able to verify -- see opcua.cpp's inner try/catch
  # around the service-body decode.
  PASS_REGULAR_EXPRESSION "\"summary\": \"Message channel=6495 token=1 \\(service type-id 712, ns=0 -- not in this decoder's dispatch table\\)\",.*\"opcua_message_size\": 5224,.*\"opcua_service_recognized\": false,.*\"opcua_service_type_id\": 712,.*\"opcua_body_shown_as_hex\": true,")

add_test(NAME real_opcua_call_request_second_session_body_rejected_as_malformed
  COMMAND conduitscope decode --format json --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap")
set_tests_properties(real_opcua_call_request_second_session_body_rejected_as_malformed PROPERTIES
  # This session's CallRequest carries a structurally-invalid MethodId NodeId encoding byte (shape
  # 0x07, outside the valid 0x00-0x05 range) -- the same real-world fuzz-test posture as the first
  # session above, just a different malformed field.
  PASS_REGULAR_EXPRESSION "\"summary\": \"Message channel=6496 token=1 \\(service type-id 712, ns=0 -- not in this decoder's dispatch table\\)\",.*\"opcua_message_size\": 110,.*\"opcua_service_recognized\": false,.*\"opcua_service_type_id\": 712,.*\"opcua_body_shown_as_hex\": true,")

add_test(NAME real_opcua_malformed_call_request_gets_error_not_response_first_session
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap" --format text)
set_tests_properties(real_opcua_malformed_call_request_gets_error_not_response_first_session PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[opcua\\]  Message channel=6495 token=1 \\(service type-id 712, ns=0 -- not in this decoder's dispatch table\\)\n.*\\[opcua\\]  Error error=Bad \\(0x80020000\\) reason=")

add_test(NAME real_opcua_malformed_call_request_gets_error_not_response_second_session
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap" --format text)
set_tests_properties(real_opcua_malformed_call_request_gets_error_not_response_second_session PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[opcua\\]  Message channel=6496 token=1 \\(service type-id 712, ns=0 -- not in this decoder's dispatch table\\)\n.*\\[opcua\\]  Error error=Bad \\(0x80070000\\) reason=")

add_test(NAME real_opcua_security_policy_none_both_sessions
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap" --format text)
set_tests_properties(real_opcua_security_policy_none_both_sessions PROPERTIES
  PASS_REGULAR_EXPRESSION "policy=http://opcfoundation.org/UA/SecurityPolicy#None OpenSecureChannelRequest.*policy=http://opcfoundation.org/UA/SecurityPolicy#None OpenSecureChannelResponse.*policy=http://opcfoundation.org/UA/SecurityPolicy#None OpenSecureChannelRequest.*policy=http://opcfoundation.org/UA/SecurityPolicy#None OpenSecureChannelResponse")

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

# Real-world S7comm-Plus (0x72) traffic -- two captures named after S7-1500 HMI/OPC
# traffic that turn out to be S7comm-Plus, not classic S7comm (see ATTRIBUTION.md's
# S7comm-Plus addendum for what each file actually contains once decoded). These are
# the same two files that, before full S7comm-Plus decoding existed, only exercised
# the old "detected, not decoded" stub -- now used to validate the real Tier-1
# decoder (GetMultiVariables/SetMultiVariables/DeleteObject) against genuine
# TIA Portal wire traffic, not just the synthetic fixture.
add_test(NAME real_s7comm_plus_db3_var1_hmi_getmultivar_request_item_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format json)
set_tests_properties(real_s7comm_plus_db3_var1_hmi_getmultivar_request_item_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"Data: Request GetMultiVariables \\(seq=19\\) \\(1 item\\(s\\)\\)\",.*\"s7plus_items\": \\[\"SYM-CRC=a9bc66e6, LID=DB3.10\"\\]")

add_test(NAME real_s7comm_plus_db3_var1_hmi_getmultivar_response_value_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format json)
set_tests_properties(real_s7comm_plus_db3_var1_hmi_getmultivar_response_value_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"Data: Response GetMultiVariables \\(seq=4\\) \\(1 value\\(s\\)\\)\",.*\"s7plus_return_code_name\": \"OK\",.*\"s7plus_values\": \\[\"item=1: \\(Byte\\) = 0x02\"\\],.*\"s7plus_integrity_digest_present\": true")

add_test(NAME real_s7comm_plus_db3_var1_hmi_deleteobject_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format json)
set_tests_properties(real_s7comm_plus_db3_var1_hmi_deleteobject_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"Data: Request DeleteObject \\(seq=12\\) \\(1 item\\(s\\)\\)\",.*\"s7plus_items\": \\[\"Delete Object Id=0x0000038a\"\\]")

# SetMultiVariables carrying a genuinely nested Struct-of-Struct value (id=1803/1804 each a
# nested Struct with a Blob member) plus a WString -- the richest single value this real
# capture exercises, and the only real-world confirmation this decoder's recursive
# decode_value_element has of struct nesting actually working end to end.
add_test(NAME real_s7comm_plus_db3_var1_hmi_setmultivar_nested_struct_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format json)
set_tests_properties(real_s7comm_plus_db3_var1_hmi_setmultivar_nested_struct_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Data: Request SetMultiVariables.*\\(WString\\) = \\\\\"1;6ES7 511-1AK00-0AB0;V1.0\\\\\".*id=1803: \\(Struct\\) Struct \\{ id=1826: \\(ULInt\\).*id=1805: \\(Blob\\) = ")

add_test(NAME real_s7comm_plus_db3_var1_hmi_setmultivar_response_ok
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format text)
set_tests_properties(real_s7comm_plus_db3_var1_hmi_setmultivar_response_ok PROPERTIES
  PASS_REGULAR_EXPRESSION "Data: Response SetMultiVariables \\(seq=2\\)")

# Connect (session handshake, PDU type 0x01) and GetVarSubStreamed remain Tier-2 (named, not
# body-decoded) -- regression guard that both are still correctly recognized on real traffic.
add_test(NAME real_s7comm_plus_db3_var1_hmi_connect_recognized_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format text)
set_tests_properties(real_s7comm_plus_db3_var1_hmi_connect_recognized_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[s7comm-plus\\]  Connect\n *note: Connect PDU \\(session establishment handshake\\) is recognized but not decoded")

add_test(NAME real_s7comm_plus_db3_var1_hmi_getvarsubstreamed_recognized_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format text)
set_tests_properties(real_s7comm_plus_db3_var1_hmi_getvarsubstreamed_recognized_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "GetVarSubStreamed request body is recognized but not decoded.*GetVarSubStreamed response body is recognized but not decoded")

# Above-COTP reassembly (trailer-absence based, not COTP's own EOT bit) confirmed on real
# TIA Portal traffic, not just the synthetic fixture.
add_test(NAME real_s7comm_plus_db3_var1_hmi_above_cotp_reassembly_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_db3_var1_hmi.pcap" --format text)
set_tests_properties(real_s7comm_plus_db3_var1_hmi_above_cotp_reassembly_note PROPERTIES
  PASS_REGULAR_EXPRESSION "reassembled a COTP/S7comm message from 419 user-data byte\\(s\\) chained across 2 complete TPKT/COTP frames")

# The "opc_request_all_types" capture's name matches its content: a single 40-item
# GetMultiVariables request/response pair that walks nearly every S7comm-Plus datatype this
# decoder knows (Bool/USInt/Byte/Word/UDInt/UInt/DInt/DWord/Int/Timestamp/LInt/LReal/Timespan/
# ULInt/LWord/Real/SInt, plus USInt arrays) -- by far the richest real-world datatype coverage
# either capture provides, and the main reason to keep this file distinct from db3_var1_hmi
# rather than only testing one of the two.
add_test(NAME real_s7comm_plus_opc_all_types_getmultivar_40_items_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/s7comm_plus_1511_opc_request_all_types.pcap" --format json)
set_tests_properties(real_s7comm_plus_opc_all_types_getmultivar_40_items_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"Data: Response GetMultiVariables \\(seq=9\\) \\(40 value\\(s\\)\\)\",.*item=22: \\(Timestamp\\) = 1970-01-01T00:00:00.000.000.000Z.*item=24: \\(LReal\\) = 0.000000.*item=25: \\(Timespan\\) = 0 ns.*item=31: \\(USInt\\) Array\\[256\\]")

# Regression guard: neither real S7comm-Plus capture should ever produce a per-item decode
# error (S7CommPlusItemError) or a ParseError-triggered "decoding stopped" note -- both
# real files decode cleanly end to end with this implementation.
foreach(s7plus_capture s7comm_plus_1511_db3_var1_hmi s7comm_plus_1511_opc_request_all_types)
  add_test(NAME real_${s7plus_capture}_no_item_errors
    COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/s7comm/${s7plus_capture}.pcap" --format json)
  set_tests_properties(real_${s7plus_capture}_no_item_errors PROPERTIES
    FAIL_REGULAR_EXPRESSION "s7plus_item_errors|decoding stopped")
endforeach()

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
# IEC 61850 MMS (ISO 9506) -- synthetic fixture (tools/make_sample_pcap.py's own build_mms_sample,
# see its docstring for the full scenario list). Session(ISO 8327-1)/Presentation(ISO 8823)/
# ACSE(ISO 8650-1)/MMS(ISO 9506-2) TLVs are hand-built to match src/mms.cpp's own decode logic --
# not captured from a real tool -- so these are regression tests for THIS decoder's own encode/
# decode round trip, not independent validation (see tests/real_captures/mms/ below for that).
# --------------------------------------------------------------------------
add_test(NAME mms_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)

add_test(NAME mms_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --stats)
set_tests_properties(mms_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +69[^\n]*\n[^\n]*\nprotocols:\n *cotp +7\n *mms +61\n *tcp +1\nmms pdu types:\n *cancel-ErrorPDU +1\n *cancel-RequestPDU +3\n *cancel-ResponsePDU +1\n *conclude-ErrorPDU +1\n *conclude-RequestPDU +4\n *conclude-ResponsePDU +1\n *confirmed-ErrorPDU +1\n *confirmed-RequestPDU +22\n *confirmed-ResponsePDU +23\n *initiate-RequestPDU +1\n *initiate-ResponsePDU +1\n *rejectPDU +1\n *unconfirmed-PDU \\(informationReport\\) +1\nmms services:\n *defineNamedVariableList +2\n *deleteNamedVariableList +2\n *fileClose +2\n *fileDelete +2\n *fileDirectory +2\n *fileOpen +2\n *fileRead +2\n *fileRename +2\n *getCapabilityList +3\n *getDomainAttributes +2\n *getNameList +3\n *getNamedVariableListAttributes +2\n *getVariableAccessAttributes +2\n *identify +4\n *informationReport +1\n *obtainFile +2\n *read +3\n *status +2\n *takeControl +2\n *write +2")

add_test(NAME mms_association_aarq_aare
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_association_aarq_aare PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mms\\]  MMS/CONNECT \\(CN\\) AARQ initiate-RequestPDU\n.*\\[mms\\]  MMS/ACCEPT \\(AC\\) AARE \\(accepted\\) initiate-ResponsePDU")

# Presentation context-definition-list (the "1=ACSE / 3=MMS" convention -- see mms.hpp) and the
# negotiated Initiate parameters, both from the AARQ frame.
add_test(NAME mms_association_presentation_and_initiate_fields
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_association_presentation_and_initiate_fields PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"MMS/CONNECT \\(CN\\) AARQ initiate-RequestPDU\",.*\"mms_presentation_contexts\": \\[\"context 1 = 2.2.1.0.1 \\(ACSE\\)\", \"context 3 = 1.0.9506.2.3 \\(MMS\\)\"\\],.*\"mms_acse_application_context_name\": \"2.2.1.0.1 \\(ACSE\\)\",.*\"proposedVersionNumber=1\", \"parameterCBB=\\[str1,str2,vnam,valt,tpy,vlis\\]\", \"servicesSupported=\\[status,getNameList,identify,read,write,getVariableAccessAttributes,defineNamedVariableList,getNamedVariableListAttributes,deleteNamedVariableList,getDomainAttributes,getCapabilityList,informationReport\\]")

add_test(NAME mms_read_request_and_response_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_read_request_and_response_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"specificationWithResult=true\", \"variable=IED1Device/GGIO1\\$ST\\$Ind1\\$stVal\"\\],.*\"mms_values\": \\[\"result\\[0\\]=true\"\\],")

add_test(NAME mms_write_request_and_response_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_write_request_and_response_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"variable=IED1Device/GGIO1\\$SP\\$Ind1\\$setVal\", \"value\\[0\\]=false\"\\],.*\"mms_values\": \\[\"result\\[0\\]=success\"\\],")

add_test(NAME mms_getnamelist_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_getnamelist_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"objectScope=domain:IED1Device\"\\],.*\"mms_values\": \\[\"listOfIdentifier=\\[LLN0,GGIO1,MMXU1\\]\", \"moreFollows=false\"\\],")

add_test(NAME mms_identify_response_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_identify_response_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"vendorName=ConduitScope Labs\", \"modelName=Virtual IED\", \"revision=1.0\", \"listOfAbstractSyntaxes=\\[1.0.9506.2.3 \\(MMS\\)\\]\"\\],")

add_test(NAME mms_getvariableaccessattributes_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_getvariableaccessattributes_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"name=IED1Device/GGIO1\\$ST\\$Ind1\\$stVal\"\\],.*\"mms_values\": \\[\"mmsDeletable=false\", \"typeSpecification=<TypeSpecification, not decoded>\"\\],")

# DefineNamedVariableList/GetNamedVariableListAttributes/DeleteNamedVariableList -- also exercises
# decode_object_name_flexible's own EXPLICIT-vs-natural-tag distinction (see mms.cpp): the request's
# own variableListName is passed as a bare, natural-tagged ObjectName, while
# GetNamedVariableListAttributes-Request wraps it EXPLICIT-style -- both must render the same name.
add_test(NAME mms_definenamedvariablelist_and_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_definenamedvariablelist_and_response PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"variableListName=MyDataSet1\", \"member\\[0\\]=IED1Device/GGIO1\\$ST\\$Ind1\\$stVal\", \"member\\[1\\]=IED1Device/GGIO1\\$ST\\$Ind2\\$stVal\"\\],.*\"mms_values\": \\[\"result=success\"\\],")

add_test(NAME mms_getnamedvariablelistattributes_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_getnamedvariablelistattributes_response PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"variableListName=MyDataSet1\"\\],.*\"mms_values\": \\[\"mmsDeletable=true\", \"member\\[0\\]=IED1Device/GGIO1\\$ST\\$Ind1\\$stVal\", \"member\\[1\\]=IED1Device/GGIO1\\$ST\\$Ind2\\$stVal\"\\],")

add_test(NAME mms_deletenamedvariablelist_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_deletenamedvariablelist_response PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"listOfVariableListName\\[0\\]=MyDataSet1\"\\],.*\"mms_values\": \\[\"numberMatched=1\", \"numberDeleted=1\"\\],")

add_test(NAME mms_getcapabilitylist_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_getcapabilitylist_response PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"listOfCapabilities=\\[STR1,VNAM,VALT\\]\", \"moreFollows=false\"\\],")

add_test(NAME mms_getdomainattributes_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_getdomainattributes_response PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"domainName=IED1Device\"\\],.*\"mms_values\": \\[\"listOfCapabilities=\\[STR1\\]\", \"state=2\", \"mmsDeletable=false\", \"sharable=true\"\\],")

# File-transfer services -- Tier1 promotion of obtainFile/fileOpen/fileRead/fileClose/fileRename/
# fileDelete/fileDirectory (see mms.cpp's own "File-transfer services" section header comment and
# docs/MANUAL.md's ROADMAP item 12). FileName's own "/"-joined rendering, GeneralizedTime's own
# reformat to ISO-8601, and FileAttributes with/without its own OPTIONAL lastModified are all
# exercised across these.
add_test(NAME mms_obtainfile_request_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_obtainfile_request_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"sourceFile=COMTRADE/fault17.dat\", \"destinationFile=fault17.dat\"\\],")

add_test(NAME mms_fileopen_request_and_response_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_fileopen_request_and_response_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"fileName=COMTRADE/fault17.dat\", \"initialPosition=0\"\\],.*\"mms_values\": \\[\"frsmID=7\", \"fileAttributes=\\{sizeOfFile=20480, lastModified=2025-01-15T12:00:00Z\\}\"\\],")

add_test(NAME mms_fileread_request_and_response_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_fileread_request_and_response_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"frsmID=7\"\\],.*\"mms_values\": \\[\"fileData=6 byte\\(s\\): cafebabe0102\", \"moreFollows=false\"\\],")

add_test(NAME mms_fileclose_request_and_null_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_fileclose_request_and_null_response PROPERTIES
  PASS_REGULAR_EXPRESSION "confirmed-RequestPDU fileClose invokeID=14\n.*confirmed-ResponsePDU fileClose invokeID=14")

add_test(NAME mms_filerename_request_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_filerename_request_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"currentFileName=COMTRADE/fault17.dat\", \"newFileName=COMTRADE/fault17_archived.dat\"\\],")

add_test(NAME mms_filedelete_request_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_filedelete_request_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"fileName=COMTRADE/fault17_archived.dat\"\\],")

# FileDirectory-Response's own listOfDirectoryEntry is the one EXPLICIT-tagged field in this whole
# section (see mms.cpp's header comment) -- two entries, one with lastModified, one without.
add_test(NAME mms_filedirectory_request_and_response_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_filedirectory_request_and_response_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_values\": \\[\"fileSpecification=COMTRADE\"\\],.*\"mms_values\": \\[\"listOfDirectoryEntry\\[0\\]=COMTRADE/fault17.cfg \\{sizeOfFile=512, lastModified=2025-01-15T12:00:00Z\\}\", \"listOfDirectoryEntry\\[1\\]=COMTRADE/fault18.dat \\{sizeOfFile=20480\\}\", \"moreFollows=true\"\\],")

# InformationReport -- this decoder's own MMS analog of its GOOSE decoder (see mms.hpp); also
# exercises Data's own utc-time (tag 17, IEC 61850-8-1 addition) rendering.
add_test(NAME mms_information_report_values
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_information_report_values PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"MMS/DATA TRANSFER / GIVE TOKENS unconfirmed-PDU \\(informationReport\\) informationReport\",.*\"mms_values\": \\[\"variable=list:MyDataSet1\", \"result\\[0\\]=true\", \"result\\[1\\]=2023-11-14T22:13:20.000Z \\[accuracy=10bit\\]\"\\],")

# Tier1/Tier2 split -- takeControl(19) is a real, named confirmedServiceRequest/Response
# alternative this decoder recognizes by name but does not further decode (mirrors the real
# tests/real_captures/mms/mms-takeControl.pcap finding): service_recognized=true, but the body is
# shown as hex, not structurally decoded.
add_test(NAME mms_tier2_takecontrol_shown_as_hex
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_tier2_takecontrol_shown_as_hex PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_service\": \"takeControl\",\n *\"mms_body_shown_as_hex\": true,\n *\"mms_body_length\": 12,\n *\"mms_body_hex\": \"800a49454431446576696365\"")

add_test(NAME mms_serviceerror_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_serviceerror_note PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mms\\]  MMS/DATA TRANSFER / GIVE TOKENS confirmed-ErrorPDU invokeID=19 error=resource\\(1\\)\n *note: additionalDescription=variable not found")

add_test(NAME mms_rejectpdu_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_rejectpdu_text PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mms\\]  MMS/DATA TRANSFER / GIVE TOKENS rejectPDU invokeID=20")

add_test(NAME mms_cancel_request_response_and_error
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_cancel_request_response_and_error PROPERTIES
  PASS_REGULAR_EXPRESSION "cancel-RequestPDU invokeID=5\n.*cancel-ResponsePDU invokeID=5\n.*cancel-RequestPDU invokeID=99\n.*cancel-ErrorPDU invokeID=99 error=cancel\\(1\\)")

# Malformed/truncated confirmedServiceRequest/Response -- invokeID present, service field missing
# entirely. Mirrors the real, genuinely truncated frame 18 of
# tests/real_captures/mms/iec61850_read.pcap (see its own ATTRIBUTION.md).
add_test(NAME mms_malformed_confirmed_request_and_response_notes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_malformed_confirmed_request_and_response_notes PROPERTIES
  PASS_REGULAR_EXPRESSION "confirmed-RequestPDU invokeID=77\n *note: confirmedServiceRequest field missing \\(malformed or truncated PDU\\)\n.*confirmed-ResponsePDU invokeID=78\n *note: confirmedServiceResponse field missing \\(malformed or truncated PDU\\)")

add_test(NAME mms_conclude_request_response_and_error
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_conclude_request_response_and_error PROPERTIES
  PASS_REGULAR_EXPRESSION "conclude-RequestPDU\n.*conclude-ResponsePDU\n.*conclude-RequestPDU\n.*conclude-ErrorPDU error=conclude\\(2\\)")

# Bare MMS -- no Session/Presentation/ACSE at all (see mms.hpp's own "Bare MMS" section).
add_test(NAME mms_bare_mms_frames
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_bare_mms_frames PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mms\\]  MMS \\(bare\\) confirmed-RequestPDU identify invokeID=1\n.*\\[mms\\]  MMS \\(bare\\) confirmed-ResponsePDU identify invokeID=1\n.*\\[mms\\]  MMS \\(bare\\) cancel-RequestPDU invokeID=1\n.*\\[mms\\]  MMS \\(bare\\) conclude-RequestPDU")

# Bare-Presentation ongoing message -- Session omitted entirely (a real shape this decoder's own
# validation found -- see mms.cpp's looks_like_bare_presentation and its ATTRIBUTION.md citation).
add_test(NAME mms_bare_presentation_no_session
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_bare_presentation_no_session PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mms\\]  MMS/\\(no Session layer\\) confirmed-RequestPDU status invokeID=1\n.*\\[mms\\]  MMS/\\(no Session layer\\) confirmed-ResponsePDU status invokeID=1")

# A single TPKT/session/presentation/MMS frame split mid-frame across two raw TCP segments --
# Decoder::reassemble_tcp_payload (the same general per-flow mechanism
# sample_tcp_reassembly.pcap's own scenario C exercises for S7comm).
add_test(NAME mms_tcp_split_reassembly
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_tcp_split_reassembly PROPERTIES
  PASS_REGULAR_EXPRESSION "buffering a TPKT/COTP PDU/frame split across TCP segments 102->49303.*waiting for more\n.*confirmed-ResponsePDU getCapabilityList invokeID=20\n *note: reassembled a TPKT/COTP PDU/frame from 63 byte\\(s\\) spanning 2 TCP segments on this flow")

add_test(NAME mms_tcp_split_reassembled_result_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_tcp_split_reassembled_result_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_service\": \"getCapabilityList\",.*\"mms_values\": \\[\"listOfCapabilities=\\[STR1,STR2,VNAM,VALT,VADR\\]\", \"moreFollows=false\"\\],")

# One MMS message chained across two COMPLETE TPKT/COTP DT frames via the EOT bit --
# Decoder::reassemble_cotp_data_frame (mirrors sample_s7comm_chaining.pcap's own scenario A): the
# split lands mid-way through a GetNameList response's own listOfIdentifier, so it only decodes
# correctly if both frames are genuinely concatenated.
add_test(NAME mms_cotp_eot_chaining
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_cotp_eot_chaining PROPERTIES
  PASS_REGULAR_EXPRESSION "beginning a COTP/S7comm message fragmented across multiple complete TPKT/COTP frames.*40 user-data byte\\(s\\) buffered.*waiting for the final.*\n.*confirmed-ResponsePDU getNameList invokeID=21\n *note: reassembled a COTP/S7comm message from 80 user-data byte\\(s\\) chained across 2 complete TPKT/COTP frames")

add_test(NAME mms_cotp_eot_chained_result_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format json)
set_tests_properties(mms_cotp_eot_chained_result_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mms_service\": \"getNameList\",.*\"mms_values\": \\[\"listOfIdentifier=\\[Domain1LLN0,Domain1GGIO1,Domain1MMXU1,Domain1XCBR1\\]\", \"moreFollows=false\"\\],")

# Two complete MMS frames coalesced by the sender/OS into one TCP segment: cotp.cpp's own COTP/
# TPKT framing decodes only the first, with an honest note about the rest (see its own "possible
# pipelined TPKT frames" comment) -- this documents that known, already-labeled limitation for MMS
# specifically, matching what the same coalescing shape already does for every other single-PDU-
# per-call COTP-based protocol in this codebase.
add_test(NAME mms_pipelined_tpkt_frames_limitation_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --format text)
set_tests_properties(mms_pipelined_tpkt_frames_limitation_note PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mms\\]  MMS \\(bare\\) conclude-RequestPDU\n *note: 9 additional byte\\(s\\) remain in this TCP segment after this TPKT frame \\(possible pipelined TPKT frames; only the first is decoded in this groundwork release\\)")

# --------------------------------------------------------------------------
# Real-world IEC 61850 MMS captures -- see tests/real_captures/mms/ATTRIBUTION.md for provenance:
# three small captures from ITI/ICS-Security-Tools's own IEC61850/MMS pcap set (one full Session/
# Presentation/ACSE association plus a Read/conclude exchange with two genuinely malformed frames;
# two entirely-bare-MMS captures, takeControl/relinquishControl and cancelRequest), plus one much
# larger (224-frame) capture this project generated itself against a real, independent MMS stack
# (mz-automation/libiec61850) rather than against this decoder's own output -- see ATTRIBUTION.md's
# own "Independent-stack validation traffic" section. Two genuine structural-gate bugs (the
# Presentation layer's own fully-encoded-data tag being mistaken for a bogus third SPDU, and
# looks_like_bare_mms_pdu missing the 3 primitive MMSpdu alternatives) were found and fixed via
# this validation -- also documented in ATTRIBUTION.md, not just fixed silently.
# --------------------------------------------------------------------------
set(MMS_REAL_CAPTURES
  iec61850_read
  mms-takeControl
  mms-cancelRequest
  libiec61850_loopback_capture
)
foreach(capture ${MMS_REAL_CAPTURES})
  add_test(NAME real_mms_${capture}_does_not_crash
    COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mms/${capture}.pcap" --format json)
endforeach()

add_test(NAME real_mms_iec61850_read_association_and_read
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mms/iec61850_read.pcap" --format text)
set_tests_properties(real_mms_iec61850_read_association_and_read PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mms\\]  MMS/CONNECT \\(CN\\) AARQ initiate-RequestPDU\n.*confirmed-RequestPDU read invokeID=0\n.*confirmed-ResponsePDU read invokeID=0\n.*conclude-RequestPDU")

# Frame 18 is a real, genuinely truncated confirmed-ResponsePDU (invokeID only, 7 bytes total on
# the wire) -- this decoder degrades to an honest note rather than guessing or crashing (see
# ATTRIBUTION.md's own "What each real capture actually contains" section).
add_test(NAME real_mms_iec61850_read_truncated_response_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mms/iec61850_read.pcap" --format text)
set_tests_properties(real_mms_iec61850_read_truncated_response_note PROPERTIES
  PASS_REGULAR_EXPRESSION "confirmed-ResponsePDU invokeID=0\n *note: confirmedServiceResponse field missing \\(malformed or truncated PDU\\)")

# Both real bare-MMS captures: entirely bare (no Session/Presentation/ACSE) real traffic, and the
# specific real fix this decoder's own validation found -- cancel-RequestPDU/conclude-RequestPDU
# are primitive, not constructed, and looks_like_bare_mms_pdu originally missed them (see
# ATTRIBUTION.md).
add_test(NAME real_mms_takecontrol_bare_sequence
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mms/mms-takeControl.pcap" --format text)
set_tests_properties(real_mms_takecontrol_bare_sequence PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mms\\]  MMS \\(bare\\) initiate-RequestPDU\n.*confirmed-RequestPDU takeControl invokeID=1\n.*confirmed-RequestPDU relinquishControl invokeID=1\n.*\\[mms\\]  MMS \\(bare\\) conclude-RequestPDU")

add_test(NAME real_mms_cancelrequest_bare_sequence
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mms/mms-cancelRequest.pcap" --format text)
set_tests_properties(real_mms_cancelrequest_bare_sequence PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mms\\]  MMS \\(bare\\) initiate-RequestPDU\n.*cancel-RequestPDU invokeID=1\n.*\\[mms\\]  MMS \\(bare\\) conclude-RequestPDU")

# Independent-stack validation traffic (mz-automation/libiec61850, 224 frames): 117 recognized as
# mms, zero parse warnings -- see ATTRIBUTION.md's own "Independent-stack validation traffic"
# section for the full methodology and the tshark 4.2.2 recursion-depth assertion failure this
# traffic also found (motivating kMaxDataRecursionDepth).
add_test(NAME real_mms_libiec61850_loopback_stats
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mms/libiec61850_loopback_capture.pcap" --stats)
set_tests_properties(real_mms_libiec61850_loopback_stats PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +224[^\n]*\n[^\n]*\nprotocols:\n *cotp +16\n *mms +117\n *tcp +91\nmms pdu types:\n *confirmed-RequestPDU +42\n *confirmed-ResponsePDU +42\n *initiate-RequestPDU +8\n *initiate-ResponsePDU +8\n *unconfirmed-PDU \\(informationReport\\) +17\nmms services:\n *getNameList +6\n *getVariableAccessAttributes +8\n *identify +2\n *informationReport +17\n *read +44\n *write +24")

add_test(NAME real_mms_libiec61850_loopback_no_parse_warnings
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mms/libiec61850_loopback_capture.pcap" --format json)
set_tests_properties(real_mms_libiec61850_loopback_no_parse_warnings PROPERTIES
  FAIL_REGULAR_EXPRESSION "warning:")

# --------------------------------------------------------------------------
# MQTT (v3.1.1/v5.0) + Sparkplug B -- synthetic fixture (tools/make_sample_pcap.py's own
# build_mqtt_sample, see its docstring/comments for the full scenario list). Hand-built to match
# src/mqtt.cpp's own decode logic -- not captured from a real tool -- so these are regression tests
# for THIS decoder's own encode/decode round trip, not independent validation (see
# tests/real_captures/mqtt/ below for that).
# --------------------------------------------------------------------------
add_test(NAME mqtt_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)

add_test(NAME mqtt_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --stats)
set_tests_properties(mqtt_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +55[^\n]*\n[^\n]*\nprotocols:\n *mqtt +52\n *tcp +3\nmqtt packet types:\n *AUTH +2\n *CONNACK +4\n *CONNECT +4\n *DISCONNECT +2\n *PINGREQ +3\n *PINGRESP +2\n *PUBACK +2\n *PUBCOMP +1\n *PUBLISH +14\n *PUBREC +1\n *PUBREL +1\n *SUBACK +4\n *SUBSCRIBE +4\n *UNSUBACK +4\n *UNSUBSCRIBE +4\nmqtt sparkplug b publishes: 8\nmqtt sparkplug b message types:\n *DBIRTH +1\n *DDATA +1\n *DDEATH +1\n *NBIRTH +1\n *NDATA +3\n *STATE +1")

# Flow A: full MQTT 3.1.1 lifecycle, port 61000.
add_test(NAME mqtt_v311_full_lifecycle_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format text)
set_tests_properties(mqtt_v311_full_lifecycle_text PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mqtt\\]  CONNECT \\(MQTT 3.1.1\\)\n.*\\[mqtt\\]  CONNACK \\(MQTT 3.1.1\\)\n.*qos=0 retain payload=6 byte\\(s\\)\n.*qos=1 id=1 payload=4 byte\\(s\\)\n.*\\[mqtt\\]  PUBACK id=1\n.*qos=2 id=2 payload=13 byte\\(s\\)\n.*\\[mqtt\\]  PUBREC id=2\n.*\\[mqtt\\]  PUBREL id=2\n.*\\[mqtt\\]  PUBCOMP id=2\n.*SUBSCRIBE \\(MQTT 3.1.1\\) id=3\n.*SUBACK \\(MQTT 3.1.1\\) id=3\n.*UNSUBSCRIBE \\(MQTT 3.1.1\\) id=4\n.*UNSUBACK \\(MQTT 3.1.1\\) id=4\n.*\\[mqtt\\]  PINGREQ\n.*\\[mqtt\\]  PINGRESP\n.*\\[mqtt\\]  DISCONNECT")

# CONNECT's own cleartext Username/Password decode (a deliberate design choice -- see mqtt.cpp's
# decode_connect comment) plus the Will fields.
add_test(NAME mqtt_v311_connect_cleartext_credentials_and_will
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v311_connect_cleartext_credentials_and_will PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"CONNECT \\(MQTT 3.1.1\\)\",.*\"mqtt_values\": \\[\"ProtocolName=\\\\\"MQTT\\\\\"\", \"ProtocolLevel=4 \\(3.1.1\\)\", \"CleanSession=true\", \"WillFlag=true\", \"WillQoS=0\", \"WillRetain=false\", \"UsernameFlag=true\", \"PasswordFlag=true\", \"KeepAlive=60s\", \"ClientId=\\\\\"plc1-hmi\\\\\"\", \"WillTopic=\\\\\"devices/plc1/lwt\\\\\"\", \"WillPayload=<7 byte\\(s\\), not decoded further>\", \"Username=\\\\\"admin\\\\\"\", \"Password=\\\\\"Passw0rd!\\\\\"\"\\]")

add_test(NAME mqtt_v311_connack_accepted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v311_connack_accepted PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"CONNACK \\(MQTT 3.1.1\\)\",.*\"mqtt_values\": \\[\"SessionPresent=false\", \"ReturnCode=0 \\(Connection Accepted\\)\"\\]")

# SUBSCRIBE/SUBACK on a session with a CONNECT already seen -- version comes from tracking, not the
# heuristic (see decoder.cpp's mqtt_session_version_).
add_test(NAME mqtt_v311_subscribe_suback_session_tracked
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v311_subscribe_suback_session_tracked PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_values\": \\[\"TopicFilter=\\\\\"devices/\\+/status\\\\\" QoS=0\", \"TopicFilter=\\\\\"devices/plc1/#\\\\\" QoS=1\"\\],.*\"notes\": \\[\"MQTT version for this SUBSCRIBE determined via this TCP session's own CONNECT \\(tracked\\)\"\\].*\"mqtt_values\": \\[\"ReasonCode=0x00 \\(Granted QoS 0\\)\", \"ReasonCode=0x01 \\(Granted QoS 1\\)\"\\],.*\"notes\": \\[\"MQTT version for this SUBACK determined via this TCP session's own CONNECT \\(tracked\\)\"\\]")

# Flow B: full MQTT 5.0 lifecycle with Properties on every applicable packet type, port 62000.
add_test(NAME mqtt_v5_full_lifecycle_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format text)
set_tests_properties(mqtt_v5_full_lifecycle_text PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[mqtt\\]  CONNECT \\(MQTT 5.0\\)\n.*\\[mqtt\\]  CONNACK \\(MQTT 5.0\\)\n.*PUBLISH \\(MQTT 5.0\\).*qos=1 id=1 payload=4 byte\\(s\\)\n.*PUBACK \\(MQTT 5.0\\) id=1\n.*SUBSCRIBE \\(MQTT 5.0\\) id=2\n.*SUBACK \\(MQTT 5.0\\) id=2\n.*UNSUBSCRIBE \\(MQTT 5.0\\) id=3\n.*UNSUBACK \\(MQTT 5.0\\) id=3\n.*\\[mqtt\\]  AUTH \\(MQTT 5.0\\)\n.*\\[mqtt\\]  AUTH \\(MQTT 5.0\\)\n.*\\[mqtt\\]  DISCONNECT \\(MQTT 5.0\\)")

# CONNECT v5's Properties block (SessionExpiryInterval/ReceiveMaximum/UserProperty on the CONNECT
# itself, WillDelayInterval inside the Will Properties) -- also regression-tests the earlier
# Modbus/CONNACK precedence collision fix (see kMaxPlausibleMbapLength in src/modbus.cpp): this
# CONNACK's own body happens to read as a plausible-looking MBAP header otherwise.
add_test(NAME mqtt_v5_connect_properties
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v5_connect_properties PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"CONNECT \\(MQTT 5.0\\)\",.*\"SessionExpiryInterval=3600\", \"ReceiveMaximum=20\", \"UserProperty: \\\\\"app\\\\\"=\\\\\"conduitscope-test\\\\\"\", \"ClientId=\\\\\"plc2-controller\\\\\"\", \"Will.WillDelayInterval=5\"")

add_test(NAME mqtt_v5_connack_properties
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v5_connack_properties PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"CONNACK \\(MQTT 5.0\\)\",.*\"mqtt_values\": \\[\"SessionPresent=false\", \"ReasonCode=0x00 \\(Success\\)\", \"ServerKeepAlive=60\", \"TopicAliasMaximum=10\"\\]")

add_test(NAME mqtt_v5_publish_properties
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v5_publish_properties PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_topic\": \"devices/plc2/temp\",.*\"mqtt_values\": \\[\"PayloadFormatIndicator=1\", \"ContentType=\\\\\"text/plain\\\\\"\"\\]")

# SubscriptionIdentifier + NoLocal + RetainHandling on a v5 SUBSCRIBE, and the corresponding
# UNSUBSCRIBE (no Properties content, but still session-tracked as v5).
add_test(NAME mqtt_v5_subscribe_properties
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v5_subscribe_properties PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"SUBSCRIBE \\(MQTT 5.0\\) id=2\",.*\"mqtt_values\": \\[\"SubscriptionIdentifier=7\", \"TopicFilter=\\\\\"devices/plc2/#\\\\\" QoS=1 NoLocal RetainHandling=0\"\\]")

# AUTH exchange (Continue authentication / Success), MQTT5-only packet type.
add_test(NAME mqtt_v5_auth_exchange
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v5_auth_exchange PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"AUTH \\(MQTT 5.0\\)\",.*\"mqtt_values\": \\[\"ReasonCode=0x18 \\(Continue authentication\\)\", \"AuthenticationMethod=\\\\\"SCRAM-SHA-256\\\\\"\", \"AuthenticationData=<8 byte\\(s\\)>\"\\].*\"summary\": \"AUTH \\(MQTT 5.0\\)\",.*\"mqtt_values\": \\[\"ReasonCode=0x00 \\(Success\\)\", \"AuthenticationMethod=\\\\\"SCRAM-SHA-256\\\\\"\"\\]")

add_test(NAME mqtt_v5_disconnect_with_reason
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v5_disconnect_with_reason PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"DISCONNECT \\(MQTT 5.0\\)\",.*\"mqtt_values\": \\[\"ReasonCode=0x04 \\(Disconnect with Will Message\\)\", \"ReasonString=\\\\\"administrative disconnect\\\\\"\"\\]")

# --------------------------------------------------------------------------
# Sparkplug B (Eclipse Tahu), flows C/C5, port 63000/63005 -- hand-rolled protobuf decode of the
# org.eclipse.tahu.protobuf.Payload/Metric messages (see mqtt.cpp's read_pb_* functions).
# --------------------------------------------------------------------------
add_test(NAME mqtt_sparkplug_nbirth_metrics
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_sparkplug_nbirth_metrics PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_topic\": \"spBv1.0/PlantA/NBIRTH/EdgeNode1\",.*\"mqtt_sparkplug_message_type\": \"NBIRTH\",.*\"mqtt_sparkplug_metrics\": \\[\"\\\\\"bdSeq\\\\\" type=UInt64 value=0\", \"\\\\\"Temperature\\\\\" type=Float value=21.500000 ts=2023-11-14T22:13:20.000Z\", \"\\\\\"Running\\\\\" type=Boolean value=true ts=2023-11-14T22:13:20.000Z\", \"\\\\\"Count\\\\\" type=Int32 value=-5 ts=2023-11-14T22:13:20.000Z\", \"\\\\\"SerialNumber\\\\\" type=String value=\\\\\"SN-00123\\\\\" ts=2023-11-14T22:13:20.000Z\", \"\\\\\"StartTime\\\\\" type=DateTime value=2023-11-14T22:13:20.000Z ts=2023-11-14T22:13:20.000Z\"\\]")

# The Int32 metric above (-5) is the non-obvious sign-reinterpretation test: Sparkplug's int_value
# is a raw uint32 wire value, NOT zigzag-encoded, so a negative signed value must be reinterpreted
# from its two's-complement bit pattern -- see render_sparkplug_metric's own comment on this.

add_test(NAME mqtt_sparkplug_dbirth_metrics
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_sparkplug_dbirth_metrics PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_topic\": \"spBv1.0/PlantA/DBIRTH/EdgeNode1/Device1\",.*\"mqtt_sparkplug_device_id\": \"Device1\",.*\"mqtt_sparkplug_metrics\": \\[\"\\\\\"Pressure\\\\\" type=Double value=101.325000 ts=2023-11-14T22:13:21.000Z\", \"\\\\\"Status\\\\\" type=Text value=\\\\\"OK\\\\\" ts=2023-11-14T22:13:21.000Z\"\\]")

# Null Boolean and an undecoded Bytes value (Tier-2 scope -- shown as a byte count, not decoded
# further, see sparkplug_datatype_name/render_sparkplug_metric's own Tier1/Tier2 split).
add_test(NAME mqtt_sparkplug_ddata_null_and_bytes_metrics
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_sparkplug_ddata_null_and_bytes_metrics PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_sparkplug_message_type\": \"DDATA\",.*\"mqtt_sparkplug_metrics\": \\[\"\\\\\"Pressure\\\\\" type=Double value=101.900000 ts=2023-11-14T22:13:23.000Z\", \"\\\\\"Fault\\\\\" type=Boolean value=null ts=2023-11-14T22:13:23.000Z\", \"\\\\\"Firmware\\\\\" type=Bytes value=<4 byte\\(s\\), not decoded further> ts=2023-11-14T22:13:23.000Z\"\\]")

add_test(NAME mqtt_sparkplug_ddeath_zero_metrics
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_sparkplug_ddeath_zero_metrics PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_sparkplug_message_type\": \"DDEATH\",.*\"mqtt_sparkplug_device_id\": \"Device1\",.*\"mqtt_sparkplug_payload_decoded\": true,.*\"mqtt_sparkplug_metric_count\": 0,")

# STATE namespace: a separate spBv1.0/STATE/{host_id} topic carrying JSON text, NOT protobuf.
add_test(NAME mqtt_sparkplug_state_topic_json_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_sparkplug_state_topic_json_text PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_topic\": \"spBv1.0/STATE/scada-host-1\",.*\"mqtt_sparkplug_message_type\": \"STATE\",.*\"mqtt_sparkplug_is_state\": true,.*\"mqtt_sparkplug_state_host_id\": \"scada-host-1\",.*\"mqtt_sparkplug_state_text\": \"\\{\\\\\"online\\\\\":true,\\\\\"timestamp\\\\\":1700000000000\\}\"")

# A deliberately malformed Sparkplug payload (a length-delimited field declaring more bytes than
# actually follow) -- decode_sparkplug_payload degrades gracefully with an honest note rather than
# crashing or silently truncating.
add_test(NAME mqtt_sparkplug_malformed_payload_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_sparkplug_malformed_payload_note PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_sparkplug_payload_decoded\": false,.*\"mqtt_sparkplug_metric_count\": 0,.*\"notes\": \\[\"Sparkplug B protobuf Payload could not be fully decoded: requested 200 bytes at offset 3 but only 6 bytes are available -- whatever metrics were found before the failure are still shown below\"\\]")

# An MQTT5 Properties block on a Sparkplug PUBLISH containing one unrecognized property id --
# decode_properties shows it as raw hex and keeps going, rather than aborting the whole message
# (the Sparkplug payload right after it still decodes correctly).
add_test(NAME mqtt_v5_unknown_property_id_and_sparkplug_still_decodes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_v5_unknown_property_id_and_sparkplug_still_decodes PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_topic\": \"spBv1.0/PlantA/NDATA/EdgeNode2\",.*\"mqtt_values\": \\[\"PayloadFormatIndicator=1\", \"\\(unknown property id 100, 1 remaining properties byte\\(s\\) not decoded: ff\\)\"\\],.*\"mqtt_sparkplug_metrics\": \\[\"\\\\\"X\\\\\" type=Int32 value=1\"\\]")

# --------------------------------------------------------------------------
# Flows D1/D2: SUBSCRIBE/SUBACK/UNSUBSCRIBE version-disambiguation HEURISTIC -- no CONNECT is ever
# seen on either flow, so decoder.cpp's mqtt_session_version_ map has nothing to go on and mqtt.cpp's
# own per-packet-type heuristic determines the shape (see mqtt.hpp's "Version disambiguation"
# section). D1 is v3.1.1-shaped, D2 is v5-shaped; both correctly resolve via SUBSCRIBE/UNSUBSCRIBE's
# stronger topic-filter-string evidence. SUBACK is documented as the weakest of the three heuristics
# (an empty/degenerate reason-code list can misresolve, since almost any byte value forms a
# "valid"-looking Properties block) -- the SUBACK responses on both flows below happen to hit exactly
# that degenerate case and resolve to v5 regardless of which flow they're on, which is expected,
# already-documented behavior, not a bug.
# --------------------------------------------------------------------------
add_test(NAME mqtt_version_heuristic_d1_v311_shape
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_version_heuristic_d1_v311_shape PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"SUBSCRIBE \\(MQTT 3.1.1\\) id=4100\",.*\"notes\": \\[\"MQTT version for this SUBSCRIBE determined via heuristic \\(only the v3.1.1-without-Properties shape parsed cleanly\\)\"\\].*\"summary\": \"UNSUBSCRIBE \\(MQTT 3.1.1\\) id=4101\",.*\"notes\": \\[\"MQTT version for this UNSUBSCRIBE determined via heuristic \\(only the v3.1.1-without-Properties shape parsed cleanly\\)\"\\]")

add_test(NAME mqtt_version_heuristic_d2_v5_shape
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_version_heuristic_d2_v5_shape PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"SUBSCRIBE \\(MQTT 5.0\\) id=4200\",.*\"notes\": \\[\"MQTT version for this SUBSCRIBE determined via heuristic \\(only the v5-with-Properties shape parsed cleanly\\)\"\\].*\"summary\": \"UNSUBSCRIBE \\(MQTT 5.0\\) id=4201\",.*\"notes\": \\[\"MQTT version for this UNSUBSCRIBE determined via heuristic \\(only the v5-with-Properties shape parsed cleanly\\)\"\\]")

add_test(NAME mqtt_version_heuristic_suback_weakest_evidence
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_version_heuristic_suback_weakest_evidence PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"SUBACK \\(MQTT 5.0\\) id=4100\",.*\"notes\": \\[\"MQTT version for this SUBACK determined via heuristic \\(a Properties block parsed cleanly within the declared Remaining Length -- the weakest-evidence heuristic of the three ambiguous MQTT packet types, see mqtt.hpp\\)\"\\]")

# --------------------------------------------------------------------------
# Flow E: one PUBLISH split mid-message across two TCP segments -- Decoder::reassemble_tcp_payload,
# driven by mqtt_declared_length. No CONNECT on this flow, so the reassembled PUBLISH also carries
# the "protocol version not known" note (PUBLISH's own version ambiguity, separate from the
# SUBSCRIBE-family heuristic above).
# --------------------------------------------------------------------------
add_test(NAME mqtt_tcp_split_reassembly
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format text)
set_tests_properties(mqtt_tcp_split_reassembly PROPERTIES
  PASS_REGULAR_EXPRESSION "buffering a MQTT packet PDU/frame split across TCP segments 65000->1883: 115 of 230 declared byte\\(s\\).*waiting for more\n.*topic=\"devices/plc1/split-test\" qos=1 id=9 payload=200 byte\\(s\\)\n *note: reassembled a MQTT packet PDU/frame from 230 byte\\(s\\) spanning 2 TCP segments on this flow\n *note: MQTT protocol version for this TCP session is not known \\(no CONNECT seen on it in this capture\\)")

# Flow F: PINGREQ + PUBACK + PINGREQ coalesced by the sender/OS into ONE TCP segment -- the
# wire_length-driven "additional MQTT packet" loop in decoder.cpp.
add_test(NAME mqtt_coalesced_packets_in_one_segment
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_coalesced_packets_in_one_segment PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"PINGREQ\",.*\"notes\": \\[\"additional MQTT packet 2 found in the same TCP payload at byte offset 2 \\(coalesced by the sender/OS\\): PUBACK id=5\", \"additional MQTT packet 3 found in the same TCP payload at byte offset 6 \\(coalesced by the sender/OS\\): PINGREQ\"\\]")

# --------------------------------------------------------------------------
# Flow G: negative/edge cases.
# --------------------------------------------------------------------------
# An invalid QoS=3 PUBLISH (MQTT-3.3.1-4 reserves QoS to 0-2) that also happens to be missing its
# Packet Identifier -- both the invalid-QoS note and the graceful "could not fully decode" note fire
# together, rather than a crash or a silent misparse.
add_test(NAME mqtt_invalid_qos_and_truncated_body_notes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_invalid_qos_and_truncated_body_notes PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_qos\": 3,.*\"mqtt_topic\": \"devices/plc1/badqos\",.*\"notes\": \\[\"PUBLISH fixed header flags declare QoS=3, which is invalid \\(MQTT-3.3.1-4 reserves QoS to 0-2\\) -- decoding continues treating it as-is\", \"could not fully decode this PUBLISH packet's own body: byte offset 22 is out of range \\(buffer size 22\\)\"\\]")

# A CONNECT-shaped byte sequence whose Protocol Name is neither "MQTT" nor "MQIsdp" -- this MUST be
# rejected outright by the structural detection gate (the stronger CONNECT-specific check in
# try_parse_mqtt_message), not decoded as MQTT at all, and must fall all the way through to the
# generic "did not match any protocol" fallback.
add_test(NAME mqtt_bogus_connect_protocol_name_rejected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format text)
set_tests_properties(mqtt_bogus_connect_protocol_name_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[tcp\\]  TCP payload of 16 byte\\(s\\) on port 55020->1883 did not match OPC UA, EtherNet/IP, IEC 104, Modbus, DNP3, COTP/S7comm/MMS, HART-IP, MQTT, or FF-HSE")

# A genuinely truncated/incomplete final packet on its own flow -- declares more Remaining Length
# than actually follows, with nothing more ever arriving in this capture -- the TCP-reassembly
# "buffering, waiting for more" path never completes, mirroring sample_opcua.pcap's own equivalent
# regression case.
add_test(NAME mqtt_truncated_final_packet_never_completes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format text)
set_tests_properties(mqtt_truncated_final_packet_never_completes PROPERTIES
  PASS_REGULAR_EXPRESSION "buffering a MQTT packet PDU/frame split across TCP segments 55030->1883: 20 of 126 declared byte\\(s\\) seen so far across 1 segment\\(s\\) on this flow, waiting for more")

# Flow H: PINGREQ/PINGRESP on a TCP session where neither port is 1883 -- the "not a configured/
# standard MQTT port" annotation (never a detection gate -- see decoder.cpp's expected_port).
add_test(NAME mqtt_unexpected_port_note
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --format json)
set_tests_properties(mqtt_unexpected_port_note PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"PINGREQ\",.*\"mqtt_packet_type\": \"PINGREQ\",.*\"mqtt_remaining_length\": 0,.*\"mqtt_is_sparkplug\": false,.*\"notes\": \\[\"seen on TCP port 52000->52001, which is not a configured/standard MQTT port \\(1883\\)\"\\]")

# --protocol mqtt / --mqtt-port CLI plumbing.
add_test(NAME mqtt_protocol_filter_only_decodes_mqtt
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --protocol mqtt --stats)
set_tests_properties(mqtt_protocol_filter_only_decodes_mqtt PROPERTIES
  PASS_REGULAR_EXPRESSION "protocols:\n *mqtt +52\n *tcp +3")

add_test(NAME mqtt_extra_port_option_accepted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --mqtt-port 52000 --mqtt-port 52001 --format json)
set_tests_properties(mqtt_extra_port_option_accepted PROPERTIES
  FAIL_REGULAR_EXPRESSION "not a configured/standard MQTT port")

# --------------------------------------------------------------------------
# Real-world MQTT captures -- see tests/real_captures/mqtt/ATTRIBUTION.md for provenance: a real
# Eclipse Paho client (MQTT 3.1, pre-OASIS "MQIsdp") talking to a broker, in two container formats
# (pcap and pcapng, confirmed byte-for-byte identical decode output), plus a third file from the
# same source that is genuinely corrupt from its very first frame -- kept and tested as-is. This
# validation found and fixed a real bug: Decoder's session version tracking didn't recognize a
# ProtocolLevel=3 (MQTT 3.1) CONNECT, only 4/5 -- see ATTRIBUTION.md's own write-up.
# --------------------------------------------------------------------------
add_test(NAME real_mqtt_packets_tcpdump_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets_tcpdump.pcap" --format json)

add_test(NAME real_mqtt_packets_pcapng_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets.pcapng" --format json)

add_test(NAME real_mqtt_pcap_and_pcapng_containers_agree
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/mqtt_pcap_pcapng_agree.sh" "$<TARGET_FILE:conduitscope>"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets_tcpdump.pcap"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets.pcapng")

# Real Eclipse Paho MQTT 3.1 (pre-OASIS "MQIsdp"/level 3) CONNECT -- the whole reason this capture
# was worth keeping: this decoder's synthetic fixture never exercises ProtocolLevel=3.
add_test(NAME real_mqtt_paho_v31_connect
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets_tcpdump.pcap" --format json)
set_tests_properties(real_mqtt_paho_v31_connect PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"CONNECT \\(MQTT 3.1\\)\",.*\"mqtt_protocol_version\": \"3.1\",.*\"mqtt_values\": \\[\"ProtocolName=\\\\\"MQIsdp\\\\\"\", \"ProtocolLevel=3 \\(3.1\\)\",.*\"ClientId=\\\\\"paho/34AAE54A75D839566E\\\\\"\"\\]")

# Regression test for the session-version-tracking fix this capture's validation found: SUBACK on a
# session whose only CONNECT was ProtocolLevel=3 must resolve via tracking, not the heuristic --
# and the PUBLISH frames on both sessions must NOT carry the "version not known" note.
add_test(NAME real_mqtt_v31_session_version_tracked_not_heuristic
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets_tcpdump.pcap" --format text)
set_tests_properties(real_mqtt_v31_session_version_tracked_not_heuristic PROPERTIES
  PASS_REGULAR_EXPRESSION "SUBSCRIBE \\(MQTT 3.1.1\\) id=1\n *note: MQTT version for this SUBSCRIBE determined via this TCP session's own CONNECT \\(tracked\\)\n.*SUBACK \\(MQTT 3.1.1\\) id=1\n *note: MQTT version for this SUBACK determined via this TCP session's own CONNECT \\(tracked\\)"
  FAIL_REGULAR_EXPRESSION "version for this SUBACK determined via heuristic|version for this TCP session is not known")

# Real client payload ("Hello from the Paho blocking client") and the retain flag on it.
add_test(NAME real_mqtt_paho_publish_payload
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets_tcpdump.pcap" --format json)
set_tests_properties(real_mqtt_paho_publish_payload PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mqtt_retain\": true,.*\"mqtt_topic\": \"SampleTopic\",.*\"mqtt_payload_length\": 35,.*\"mqtt_payload_hex\": \"48656c6c6f2066726f6d20746865205061686f20626c6f636b696e6720636c69656e74\"")

# Two complete MQTT packets (PUBLISH + DISCONNECT) genuinely coalesced by the real client/OS into
# one TCP segment -- previously only exercised by this project's own synthetic Flow F.
add_test(NAME real_mqtt_coalesced_publish_disconnect
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets_tcpdump.pcap" --format json)
set_tests_properties(real_mqtt_coalesced_publish_disconnect PROPERTIES
  PASS_REGULAR_EXPRESSION "\"notes\": \\[\"additional MQTT packet 2 found in the same TCP payload at byte offset 25 \\(coalesced by the sender/OS\\): DISCONNECT\"\\]")

add_test(NAME real_mqtt_no_undecoded_notes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets_tcpdump.pcap" --format text)
set_tests_properties(real_mqtt_no_undecoded_notes PROPERTIES
  FAIL_REGULAR_EXPRESSION "could not fully decode|warning:")

# The RedHat61 file is genuinely corrupt from its very first frame (see ATTRIBUTION.md's own byte-
# level analysis) -- this decoder must reject it with a clear error, not crash or silently misparse.
add_test(NAME real_mqtt_redhat61_corrupt_file_reports_clear_error
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/mqtt/mqtt_packets_RedHat61_tcpdump.pcap" --format text)
set_tests_properties(real_mqtt_redhat61_corrupt_file_reports_clear_error PROPERTIES
  PASS_REGULAR_EXPRESSION "error: '.*mqtt_packets_RedHat61_tcpdump\\.pcap' reports an implausible captured length \\([0-9]+ bytes\\) -- the file is likely truncated or corrupt")


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

# --------------------------------------------------------------------------
# PLC Control (0x28) / PLC Stop (0x29) parameter decoding -- tests/sample_s7comm_pi_control.pcap,
# see tools/make_sample_pcap.py's own build_s7comm_pi_control_sample() docstring for the full
# scenario list. s7comm_known_function_names()/s7comm_function_name() themselves are untouched --
# these two function codes were already named there; only their parameter decoding is new here.
# --------------------------------------------------------------------------

add_test(NAME s7comm_plc_stop_message_decoded_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_plc_stop_message_decoded_text PROPERTIES
  PASS_REGULAR_EXPRESSION "Job: PLC Stop \\(\"PLC_STOP\"\\)")

add_test(NAME s7comm_plc_stop_message_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format json)
set_tests_properties(s7comm_plc_stop_message_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7comm_plc_stop_message\": \"PLC_STOP\"")

add_test(NAME s7comm_pi_control_insert_two_blocks_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_insert_two_blocks_text PROPERTIES
  PASS_REGULAR_EXPRESSION "Job: PLC Control \\(_INSE - Activates a PLC module, 2 block\\(s\\): DB100 \\(Passive\\), FC5 \\(Active\\)\\)")

add_test(NAME s7comm_pi_control_insert_two_blocks_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format json)
set_tests_properties(s7comm_pi_control_insert_two_blocks_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7comm_pi_service_name\": \"_INSE\",\n *\"s7comm_pi_service_description\": \"Activates a PLC module\",[^}]*\"s7comm_pi_control_blocks\": \\[\"DB100 \\(Passive\\)\", \"FC5 \\(Active\\)\"\\]")

add_test(NAME s7comm_pi_control_delete_block_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_delete_block_text PROPERTIES
  PASS_REGULAR_EXPRESSION "Job: PLC Control \\(_DELE - Removes module from the PLC's passive file system, 1 block\\(s\\): DB50 \\(Active as well as passive\\)\\)")

add_test(NAME s7comm_pi_control_pprogram_empty_argument_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_pprogram_empty_argument_text PROPERTIES
  PASS_REGULAR_EXPRESSION "Job: PLC Control \\(P_PROGRAM - PLC Start / Stop\\)\n")

add_test(NAME s7comm_pi_control_pprogram_argument_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_pprogram_argument_text PROPERTIES
  PASS_REGULAR_EXPRESSION "Job: PLC Control \\(P_PROGRAM - PLC Start / Stop, arg=\"OB1\"\\)")

add_test(NAME s7comm_pi_control_pprogram_argument_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format json)
set_tests_properties(s7comm_pi_control_pprogram_argument_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7comm_pi_control_argument\": \"OB1\"")

# Sinumerik/CNC-specific PI service name: the name+description lookup must fire, but the
# parameter block itself must be explicitly noted as NOT decoded (the deliberate scope boundary).
add_test(NAME s7comm_pi_control_sinumerik_name_lookup_only_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_sinumerik_name_lookup_only_text PROPERTIES
  PASS_REGULAR_EXPRESSION "Job: PLC Control \\(_N_F_XFER - Selects file for uploading\\)\n *note: PLC Control PI service \"_N_F_XFER\" \\(Selects file for uploading\\) has a 4-byte parameter block that is not decoded -- Sinumerik/CNC-specific")

add_test(NAME s7comm_pi_control_non_numeric_block_number_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_non_numeric_block_number_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "non-numeric block number \\(ABCDE\\)")

add_test(NAME s7comm_pi_control_truncated_block_descriptor_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_truncated_block_descriptor_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: PLC Control block descriptor 1 is truncated \\(need 8 bytes, have 0\\)")

add_test(NAME s7comm_pi_control_response_status_both_flags_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_response_status_both_flags_text PROPERTIES
  PASS_REGULAR_EXPRESSION "Ack_Data: PLC Control \\(more data=yes, error=yes\\)")

add_test(NAME s7comm_pi_control_response_status_no_flags_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_response_status_no_flags_text PROPERTIES
  PASS_REGULAR_EXPRESSION "Ack_Data: PLC Control \\(more data=no, error=no\\)")

add_test(NAME s7comm_pi_control_response_status_in_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format json)
set_tests_properties(s7comm_pi_control_response_status_in_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7comm_pi_control_has_more_data\": true,\n *\"s7comm_pi_control_has_error\": true,.*\"s7comm_pi_control_has_more_data\": false,\n *\"s7comm_pi_control_has_error\": false,")

# Malformed/truncated 0x29 and 0x28 packets must degrade gracefully -- a note, never a crash or a
# thrown ParseError escaping try_parse_s7comm (see s7comm.hpp's tolerant-parsing convention).
add_test(NAME s7comm_plc_stop_truncated_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_plc_stop_truncated_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: PLC Stop parameter block is too short to contain its reserved bytes and message-length field")

add_test(NAME s7comm_pi_control_truncated_reserved_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_truncated_reserved_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: PLC Control parameter block is too short to contain its reserved bytes and PI parameter-length field")

add_test(NAME s7comm_pi_control_declared_paramlen_exceeds_available_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format text)
set_tests_properties(s7comm_pi_control_declared_paramlen_exceeds_available_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: PLC Control PI parameter block is truncated \\(declares 50 byte\\(s\\), only 3 available\\)\n *note: PLC Control parameter block is missing its PI service name length byte")

add_test(NAME s7comm_pi_control_sample_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format json)

add_test(NAME s7comm_pi_control_sample_csv_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --format csv)

add_test(NAME s7comm_pi_control_sample_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_pi_control.pcap" --stats)
set_tests_properties(s7comm_pi_control_sample_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "s7comm function codes:\n *PLC Control +[0-9]+\n *PLC Stop +[0-9]+")

# --------------------------------------------------------------------------
# S7comm-Plus (0x72) -- tests/sample_s7commplus.pcap, see tools/make_sample_pcap.py's own
# build_s7commplus_sample() docstring for the full scenario list. Validated against real TIA
# Portal traffic too -- see the real_s7comm_plus_* cases above and
# tests/real_captures/s7comm/ATTRIBUTION.md's own S7comm-Plus addendum.
# --------------------------------------------------------------------------

# GetMultiVariables request: all five item-address shapes decode_item_address branches on, in one
# request -- symbolic Merker (no extra LID), symbolic DB with a nested LID, an unrecognized IQMCT
# area code, a wholly unrecognized area1/area2 pair, and object-ID-style addressing.
add_test(NAME s7commplus_getmultivar_request_item_address_shapes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_getmultivar_request_item_address_shapes PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"Data: Request GetMultiVariables \\(seq=1\\) \\(5 item\\(s\\)\\)\",.*\"s7plus_items\": \\[\"SYM-CRC=ea2db0d9, LID=M\", \"SYM-CRC=a9bc66e6, LID=DB5.10\", \"SYM-CRC=11111111, LID=Unknown IQMCT area 0x0099\", \"SYM-CRC=22222222, LID=Unknown area 0x1234/0x5678\", \"by IDs: RID=100, ID=500, ID=7\"\\]")

# GetMultiVariables response: scalar Int, Array of (signed varint) DInt, Addressarray of UInt,
# Sparsearray of Byte, a genuinely nested Struct-of-Struct with a WString leaf, LReal, Timestamp,
# Timespan, Blob, and a per-item error -- effectively every datatype/array-kind this decoder
# supports in one response.
add_test(NAME s7commplus_getmultivar_response_all_datatype_shapes
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_getmultivar_response_all_datatype_shapes PROPERTIES
  PASS_REGULAR_EXPRESSION "item=1: \\(Int\\) = -1234.*item=2: \\(DInt\\) Array\\[3\\] = \\[1, 2, -3\\].*item=3: \\(UInt\\) Addressarray\\[2\\] = \\[10, 20\\].*item=4: \\(Byte\\) Sparsearray = \\[0xaa, 0xbb\\].*id=315: \\(UDInt\\) = 320; id=316: \\(Struct\\) Struct \\{ id=1826: \\(ULInt\\) = 123456789; id=1827: \\(UDInt\\) = 42 \\}; id=317: \\(WString\\) = .V1.0;6ES7 511-1AK00-0AB0.*item=6: \\(LReal\\) = 3.141593.*item=7: \\(Timestamp\\) = 2024-09-10T20:26:40.*item=8: \\(Timespan\\) = 1500000000 ns.*item=9: \\(Blob\\) = 000102030405.*item=10: Object not found \\(-12\\)")

add_test(NAME s7commplus_getmultivar_response_integrity_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_getmultivar_response_integrity_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"Data: Response GetMultiVariables \\(seq=1\\) \\(9 value\\(s\\)\\)\",.*\"s7plus_integrity_digest_present\": true")

# GetMultiVariables request/response via the "subscribed link" item-number path (link_id != 0) --
# a materially different request shape from the item-address list above.
add_test(NAME s7commplus_getmultivar_subscribed_link_request
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_getmultivar_subscribed_link_request PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7plus_items\": \\[\"by subscribed Link-Id=42, ID=1\", \"by subscribed Link-Id=42, ID=2\", \"by subscribed Link-Id=42, ID=3\"\\]")

add_test(NAME s7commplus_getmultivar_subscribed_link_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_getmultivar_subscribed_link_response PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7plus_values\": \\[\"item=1: \\(Bool\\) = 0x01\", \"item=2: \\(Bool\\) = 0x00\", \"item=3: \\(USInt\\) = 7\"\\]")

# SetMultiVariables -- marker==0 (native symbolic item-address) request shape, and its response.
add_test(NAME s7commplus_setmultivar_marker0_request
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_setmultivar_marker0_request PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7plus_items\": \\[\"SYM-CRC=deadbeef, LID=M\", \"SYM-CRC=cafef00d, LID=DB5.20\"\\],.*\"s7plus_values\": \\[\"id=1: \\(Real\\) = 98.599998\", \"id=2: \\(DWord\\) = 0xdeadbeef\"\\]")

add_test(NAME s7commplus_setmultivar_marker0_response_ok
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_setmultivar_marker0_response_ok PROPERTIES
  PASS_REGULAR_EXPRESSION "Data: Response SetMultiVariables \\(seq=3\\)")

# SetMultiVariables -- marker!=0 (object-ID) request shape, and a response carrying a genuine
# per-item write failure (Invalid CRC), not just success.
add_test(NAME s7commplus_setmultivar_marker_object_id_request
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_setmultivar_marker_object_id_request PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7plus_items\": \\[\"in Object Id=0x00000388, ID=306\", \"in Object Id=0x00000388, ID=305\"\\]")

add_test(NAME s7commplus_setmultivar_response_item_error
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_setmultivar_response_item_error PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7plus_item_errors\": \\[\"item=2: Invalid CRC \\(-17\\)\"\\]")

# SetVariable and DeleteObject request/response pairs -- DeleteObject's response side is only
# validated here (the real captures never showed one, only the request -- see ATTRIBUTION.md).
add_test(NAME s7commplus_setvariable_request_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_setvariable_request_response PROPERTIES
  PASS_REGULAR_EXPRESSION "\"s7plus_items\": \\[\"SetVariable in Object Id=0x00000390\"\\],.*\"s7plus_values\": \\[\"id=1: \\(Bool\\) = 0x01\"\\].*Data: Response SetVariable \\(seq=5\\)")

add_test(NAME s7commplus_deleteobject_request_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)
set_tests_properties(s7commplus_deleteobject_request_response PROPERTIES
  PASS_REGULAR_EXPRESSION "\"summary\": \"Data: Request DeleteObject \\(seq=6\\) \\(1 item\\(s\\)\\)\",.*\"s7plus_items\": \\[\"Delete Object Id=0x0000039a\"\\].*\"summary\": \"Data: Response DeleteObject \\(seq=6\\) \\(1 item\\(s\\)\\)\",.*\"s7plus_return_code_name\": \"OK\",.*\"s7plus_items\": \\[\"Delete Object Id=0x0000039a\"\\]")

# Tier-2 (named, not body-decoded) shapes: Connect (both directions), Notification, DataFW1_5
# (header-only decode), and an "other" function code (Explore) neither direction decodes.
add_test(NAME s7commplus_connect_both_directions_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_connect_both_directions_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[s7comm-plus\\]  Connect\n *note: Connect PDU.*\\[s7comm-plus\\]  Connect\n *note: Connect PDU")

add_test(NAME s7commplus_notification_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_notification_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Data: Notification\n *note: Notification body \\(subscribed/cyclic variable updates\\) is recognized but not decoded")

add_test(NAME s7commplus_datafw1_5_header_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_datafw1_5_header_only PROPERTIES
  PASS_REGULAR_EXPRESSION "DataFW1_5 \\(24 byte\\(s\\) data, not decoded\\)\n *note: DataFW1_5 PDU \\(firmware >= V1.5\\) moves its Integrity part")

add_test(NAME s7commplus_other_function_code_not_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_other_function_code_not_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "Explore request body is recognized but not decoded.*Explore response body is recognized but not decoded")

# Keep Alive: its own distinct 4-byte header-only framing, no Data part, no trailer.
add_test(NAME s7commplus_keepalive_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_keepalive_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[s7comm-plus\\]  Keep Alive \\(seq=9\\)")

# Edge cases exercising the Data part's own try/catch -- both must degrade to a clear note, never
# a crash or a silently wrong decode. The array-of-Struct case is a regression guard for a real
# bug this project's own code review caught (and fixed) before this decoder was ever built.
add_test(NAME s7commplus_array_of_struct_rejected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_array_of_struct_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "S7comm-Plus Data part decoding stopped: an array of Struct values was encountered -- this decoder does not support delimiting per-element nested member lists")

add_test(NAME s7commplus_unrecognized_datatype_s7string_rejected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_unrecognized_datatype_s7string_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "S7comm-Plus Data part decoding stopped: unrecognized S7comm-Plus value datatype 0x19")

# A telegram missing its trailer -- S7comm-Plus's own above-COTP fragmentation signal (NOT COTP's
# own EOT bit), which this decoder does not reassemble across, only reports.
add_test(NAME s7commplus_missing_trailer_fragment_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_missing_trailer_fragment_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "Data \\(fragment, awaiting further data\\)\n *note: S7comm-Plus telegram has no trailer in this frame -- it continues in a further TPKT/COTP frame")

# A telegram too short even for the fixed 4-byte header -- surfaced via the decoder's outer
# catch(ParseError) as protocol=parse-error, not a partial/guessed S7comm-Plus decode.
add_test(NAME s7commplus_truncated_header_is_parse_error
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_truncated_header_is_parse_error PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[parse-error\\]  could not parse packet: S7comm-Plus header is truncated \\(need 4 bytes, have 2\\)")

# A session on a TCP port pair that is neither 102 nor a configured --s7comm-port addition.
add_test(NAME s7commplus_unexpected_port_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format text)
set_tests_properties(s7commplus_unexpected_port_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "seen on TCP port 50303->50304, which is not a configured/standard COTP/S7comm port \\(102\\)")

add_test(NAME s7commplus_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format json)

add_test(NAME s7commplus_csv_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --format csv)

add_test(NAME s7commplus_stats_counted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --stats)
set_tests_properties(s7commplus_stats_counted PROPERTIES
  PASS_REGULAR_EXPRESSION "s7comm-plus")

# Regression guard for a documented custom --protocol/policy-validate value: "s7comm-plus" must be
# accepted, and --stats confirms the full PDU-type/function/Tier-1 breakdown this fixture is meant
# to exercise (note: the COTP Connection Request/Confirm frames still show up as their own "cotp"
# protocol -- COTP-level framing is always surfaced, matching classic S7comm/MMS's own filters).
add_test(NAME s7commplus_protocol_filter
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7commplus.pcap" --protocol s7comm-plus --stats)
set_tests_properties(s7commplus_protocol_filter PROPERTIES
  PASS_REGULAR_EXPRESSION "protocols:\n *cotp +2\n *parse-error +1\n *s7comm-plus +23\ns7comm-plus pdu types:\n *Connect +2\n *Data +18\n *DataFW1_5 +1\n *Keep Alive +2\ns7comm-plus functions:\n *DeleteObject +2\n *Explore +2\n *GetMultiVariables +6\n *SetMultiVariables +4\n *SetVariable +2\ns7comm-plus function bodies fully decoded \\(Tier 1\\): 12")

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

# --------------------------------------------------------------------------
# FOUNDATION Fieldbus HSE (FDA/SM/FMS/LAN Redundancy) -- tests/sample_ffhse.pcap, see
# tools/make_sample_pcap.py's own build_ffhse_sample() docstring for the full scenario list.
# --------------------------------------------------------------------------

# FDA Open Session Req/Rsp/Err -- the Rsp also carries a Message-Number + Invoke-Id trailer.
add_test(NAME ffhse_fda_open_session_req_rsp_err
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fda_open_session_req_rsp_err PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FDA Open Session Req\",.*\"ffhse_values\": \\[\"session-index=1\", \"max-buffer-size=8192\", \"max-msg-length=8192\", \"reserved=0x00\", \"nma-configuration-use=1 \\(NMA Configuration Permitted\\)\".*\"ffhse_message_number\": 1,.*\"ffhse_invoke_id\": 1,.*\"ffhse_message_name\": \"FDA Open Session Rsp\".*\"ffhse_message_name\": \"FDA Open Session Err\",.*\"error-class=5 \\(Service\\)\", \"error-code=6 \\(unsupported service\\)\"")

# FDA Idle Req/Rsp (both expected empty) and an FDA service id this decoder does not recognize.
add_test(NAME ffhse_fda_idle_and_unrecognized_service
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fda_idle_and_unrecognized_service PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FDA Idle Req\",.*\"ffhse_body_decoded\": true.*\"ffhse_message_name\": \"FDA Idle Rsp\",.*\"ffhse_message_name\": \"FDA service 2\",.*\"ffhse_recognized\": false,.*\"ffhse_body_shown_as_hex\": true.*FDA service id 2 is not recognized by this decoder -- shown as raw hex")

# SM Find Tag Query Req and SM Find Tag Reply Req (unconfirmed) -- the Reply's own FDA Address
# Selector list (2 entries).
add_test(NAME ffhse_sm_find_tag_query_and_reply
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_sm_find_tag_query_and_reply PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"SM Find Tag Query Req\",.*\"query-type=0 \\(PD Tag query for primary device\\)\".*\"ffhse_message_name\": \"SM Find Tag Reply Req\",.*\"fda-address-selector\\[0\\]=0x1111\", \"fda-address-selector\\[1\\]=0x2222\"")

# SM Identify Rsp on BOTH LinkId branches -- the single trickiest piece of this decoder (see
# ffhse.hpp's own "The LinkId branch" section): LinkId != 0 decodes the trailing list as 2-byte
# H1NodeAddress+VersionNumber pairs; LinkId == 0 decodes it as 4-byte H1LinkId+Reserved+Version
# quads -- same total byte count, different internal shape.
add_test(NAME ffhse_sm_identify_linkid_nonzero_branch
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_sm_identify_linkid_nonzero_branch PROPERTIES
  PASS_REGULAR_EXPRESSION "\"version-number-list\\[0\\].a=h1-node-address=0x01 version=1\", \"version-number-list\\[0\\].b=h1-node-address=0x02 version=1\".*LinkId \\(this PDU's own header FDA Address, upper 16 bits\\) = 0x0005 -- version-number-list decoded as H1NodeAddress\\+VersionNumber pairs")

add_test(NAME ffhse_sm_identify_linkid_zero_branch
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_sm_identify_linkid_zero_branch PROPERTIES
  PASS_REGULAR_EXPRESSION "\"version-number-list\\[0\\]=h1-link-id=0x0005 version=1\", \"version-number-list\\[1\\]=h1-link-id=0x0006 version=2\".*LinkId \\(this PDU's own header FDA Address, upper 16 bits\\) = 0x0000 -- version-number-list decoded as H1LinkId\\+Reserved\\+VersionNumber quads")

# SM Device Annunciation Req (unconfirmed) reuses the SAME 108-byte-plus-list shape as SM
# Identify Rsp, on both LinkId branches again.
add_test(NAME ffhse_sm_device_annunciation_both_linkid_branches
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_sm_device_annunciation_both_linkid_branches PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"SM Device Annunciation Req\",.*H1NodeAddress\\+VersionNumber pairs.*\"ffhse_message_name\": \"SM Device Annunciation Req\",.*H1LinkId\\+Reserved\\+VersionNumber quads")

# SM Clear Address Req/Rsp (confirmed) -- Rsp is expected empty.
add_test(NAME ffhse_sm_clear_address_req_rsp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_sm_clear_address_req_rsp PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"SM Clear Address Req\",.*\"interface-to-clear=0x01\".*\"ffhse_message_name\": \"SM Clear Address Rsp\",.*\"ffhse_body_decoded\": true")

# SM Set Assignment Info Req/Rsp (two DIFFERENT body shapes) and its own Err.
add_test(NAME ffhse_sm_set_assignment_info_req_rsp_err
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_sm_set_assignment_info_req_rsp_err PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"SM Set Assignment Info Req\",.*\"h1-new-address=0x05\".*\"ffhse_message_name\": \"SM Set Assignment Info Rsp\",.*\"max-device-index=8\", \"hse-repeat-time=1000\".*\"ffhse_message_name\": \"SM Set Assignment Info Err\",.*\"error-class=5 \\(Service\\)\", \"error-code=12 \\(assignments already made\\)\"")

# SM Clear Assignment Info Req/Rsp (Rsp expected empty) and an SM unconfirmed service id this
# decoder does not recognize.
add_test(NAME ffhse_sm_clear_assignment_and_unrecognized_service
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_sm_clear_assignment_and_unrecognized_service PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"SM Clear Assignment Info Req\",.*\"ffhse_message_name\": \"SM Clear Assignment Info Rsp\",.*\"ffhse_message_name\": \"SM unconfirmed service 7\",.*SM unconfirmed service id 7 is not recognized by this decoder -- shown as raw hex")

# FMS Initiate Req/Rsp/Err -- the Rsp also carries a full 8-byte Time Stamp trailer.
add_test(NAME ffhse_fms_initiate_req_rsp_err_with_timestamp_trailer
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fms_initiate_req_rsp_err_with_timestamp_trailer PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FMS Initiate Req\",.*\"connect-option=1 \\(VCR Selector\\)\".*\"ffhse_time_stamp\": 72623859790382856,.*\"ffhse_message_name\": \"FMS Initiate Rsp\",.*\"ver-od-called=1\", \"prof-num-called=1\".*\"ffhse_message_name\": \"FMS Initiate Err\",.*\"error-class=11 \\(FMS Initiate\\)\", \"error-code=2 \\(feature-not-supported\\)\"")

# FMS Status Req (empty)/Rsp and FMS Identify Req (empty)/Rsp.
add_test(NAME ffhse_fms_status_and_identify
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fms_status_and_identify PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FMS Status Req\",.*\"ffhse_message_name\": \"FMS Status Rsp\",.*\"logical-status=0x00\", \"physical-status=0x00\", \"local-detail=0\".*\"ffhse_message_name\": \"FMS Identify Req\",.*\"ffhse_message_name\": \"FMS Identify Rsp\",.*\"vendor-name=..Yokogawa")

# FMS Read / Read with Subindex -- the Req's Index is decoded, but the Rsp's own returned VALUE
# is deliberately left raw (no self-describing wire type without external Object Dictionary
# context) -- see ffhse.hpp's Tier-1/Tier-2 split paragraph.
add_test(NAME ffhse_fms_read_and_read_with_subindex_value_left_raw
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fms_read_and_read_with_subindex_value_left_raw PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FMS Read Req\",.*\"ffhse_values\": \\[\"index=315\"\\].*\"ffhse_message_name\": \"FMS Read Rsp\",.*has no self-describing wire type without external Object Dictionary context.*\"ffhse_message_name\": \"FMS Read with Subindex Req\",.*\"index=316\", \"subindex=2\".*\"ffhse_message_name\": \"FMS Read with Subindex Rsp\",.*has no self-describing wire type")

# FMS Write / Write with Subindex -- Index is genuinely decoded, but Data is left raw hex inline
# (same reasoning as Read's own value).
add_test(NAME ffhse_fms_write_and_write_with_subindex_data_left_raw
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fms_write_and_write_with_subindex_data_left_raw PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FMS Write Req\",.*\"index=315\".*\"ffhse_body_hex\": \"42a00000\",.*Write Data has no self-describing wire type.*\"ffhse_message_name\": \"FMS Write Rsp\",.*\"ffhse_message_name\": \"FMS Write with Subindex Req\",.*\"index=316\", \"subindex=2\".*Write Data has no self-describing wire type")

# The FMS unconfirmed Information Report family -- 2 body shapes reused across 4 service ids
# (plain Index+Data vs Index+Subindex+Data).
add_test(NAME ffhse_fms_information_report_family
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fms_information_report_family PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FMS Information Report Req\",.*\"ffhse_values\": \\[\"index=315\"\\].*\"ffhse_message_name\": \"FMS Information Report with Subindex Req\",.*\"index=316\", \"subindex=2\".*\"ffhse_message_name\": \"FMS Information Report On Change Req\",.*\"ffhse_message_name\": \"FMS Information Report On Change with Subindex Req\",.*\"index=316\", \"subindex=2\"")

# FMS Unsolicited Status Req (unconfirmed, same 8-byte shape as the confirmed Status Rsp) and
# FMS Abort (unconfirmed).
add_test(NAME ffhse_fms_unsolicited_status_and_abort
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fms_unsolicited_status_and_abort PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FMS Unsolicited Status Req\",.*\"logical-status=0x01\", \"physical-status=0x00\", \"local-detail=5\".*\"ffhse_message_name\": \"FMS Abort Req\",.*\"abort-detail=000102030405060708090a0b0c0d0e0f\", \"abort-id=0x01\", \"reason-code=0x02\"")

# FMS Event Notification Req (unconfirmed) -- Tier 2, shown as raw hex.
add_test(NAME ffhse_fms_event_notification_tier2
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fms_event_notification_tier2 PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FMS Event Notification Req\",.*\"ffhse_recognized\": true,.*\"ffhse_body_decoded\": false,.*\"ffhse_body_shown_as_hex\": true.*this decoder does not further decode message FMS Event Notification -- shown as raw hex")

# FMS Get OD Req/Rsp (confirmed) -- Tier 2, both directions, with the note that even the
# reference Wireshark dissector leaves OD entries undecoded.
add_test(NAME ffhse_fms_get_od_tier2_both_directions
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fms_get_od_tier2_both_directions PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FMS Get OD Req\",.*even the reference Wireshark dissector leaves FMS Get OD entries undecoded.*\"ffhse_message_name\": \"FMS Get OD Rsp\",.*even the reference Wireshark dissector leaves FMS Get OD entries undecoded")

# An FMS confirmed AND an FMS unconfirmed service id this decoder does not recognize.
add_test(NAME ffhse_fms_confirmed_and_unconfirmed_unrecognized_service
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_fms_confirmed_and_unconfirmed_unrecognized_service PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FMS confirmed service 50\",.*FMS confirmed service id 50 is not recognized by this decoder.*\"ffhse_message_name\": \"FMS unconfirmed service 99\",.*FMS unconfirmed service id 99 is not recognized by this decoder")

# LAN Redundancy Get Info Req (empty)/Rsp and Put Info Req/Rsp (identical shape both directions).
add_test(NAME ffhse_lan_get_and_put_info
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_lan_get_and_put_info PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"LAN Redundancy Get Info Req\",.*\"ffhse_message_name\": \"LAN Redundancy Get Info Rsp\",.*\"max-msg-num-diff=1 \\(Do not detect a fault\\)\".*\"lr-flags-flag=cross-cable\", \"lr-flags-flag=multi-trans\".*\"ffhse_message_name\": \"LAN Redundancy Put Info Req\",.*\"ffhse_message_name\": \"LAN Redundancy Put Info Rsp\"")

# LAN Redundancy Get Statistics Req (empty)/Rsp (2 XCableStat entries) and its own Err.
add_test(NAME ffhse_lan_get_statistics_req_rsp_err
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_lan_get_statistics_req_rsp_err PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"LAN Redundancy Get Statistics Req\",.*\"ffhse_message_name\": \"LAN Redundancy Get Statistics Rsp\",.*\"num-x-cable-stat=2\", \"x-cable-stat\\[0\\]=5\", \"x-cable-stat\\[1\\]=7\".*\"ffhse_message_name\": \"LAN Redundancy Get Statistics Err\",.*\"error-class=8 \\(Other\\)\"")

# LAN Redundancy Diagnostic Message Req (unconfirmed) -- 1 interface-status entry across all 4
# parallel lists (A-to-A/B-to-A/A-to-B/B-to-B).
add_test(NAME ffhse_lan_diagnostic_message
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_lan_diagnostic_message PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"LAN Redundancy Diagnostic Message Req\",.*\"if-a-to-a-status\\[0\\]=1\", \"if-b-to-a-status\\[0\\]=0\", \"if-a-to-b-status\\[0\\]=1\", \"if-b-to-b-status\\[0\\]=0\"")

# LAN Redundancy unconfirmed AND confirmed service ids this decoder does not recognize.
add_test(NAME ffhse_lan_unrecognized_services
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_lan_unrecognized_services PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"LAN Redundancy unconfirmed service 5\",.*LAN Redundancy unconfirmed service id 5 is not recognized.*\"ffhse_message_name\": \"LAN Redundancy confirmed service 9\",.*LAN Redundancy confirmed service id 9 is not recognized")

# A message with ALL FOUR optional trailer fields present at once (Options 0xE8 = 232).
add_test(NAME ffhse_all_four_trailer_fields_present
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_all_four_trailer_fields_present PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_options\": 232,.*\"ffhse_message_number\": 7,.*\"ffhse_invoke_id\": 8,.*\"ffhse_time_stamp\": 1234605616436508552,.*\"ffhse_extended_control_field\": 168496141,.*\"ffhse_message_name\": \"FMS Status Req\"")

# The decorative Pad Length sub-field (Options low 3 bits) is surfaced (as part of the raw
# Options byte) but plays no role in this decoder's own length arithmetic -- see ffhse.hpp's
# Options paragraph.
add_test(NAME ffhse_pad_length_decorative_not_acted_on
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_pad_length_decorative_not_acted_on PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_options\": 7,.*\"ffhse_message_name\": \"FDA Idle Req\",.*\"ffhse_recognized\": true,.*\"ffhse_body_decoded\": true")

# Two FF-HSE PDUs concatenated into ONE UDP datagram -- exercises the wire_length-driven
# coalescing while-loop in decoder.cpp's UDP dispatch.
add_test(NAME ffhse_udp_multi_pdu_coalescing
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_udp_multi_pdu_coalescing PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"FDA Idle Req\",.*additional FF-HSE PDU 2 found in the same UDP datagram at byte offset 12: FDA Idle Rsp")

# Malformed/truncated: Message Length claims a full 52-byte FDA Open Session Req body, but only
# 20 bytes of it are actually present -- exercises both the "declares more than available" note
# and require_min's own fallback to raw hex, never a crash or a silently wrong decode.
add_test(NAME ffhse_malformed_truncated_body_falls_back_to_raw_hex
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_malformed_truncated_body_falls_back_to_raw_hex PROPERTIES
  PASS_REGULAR_EXPRESSION "FF-HSE message declares Message Length 64 but only 32 byte\\(s\\) are available -- truncated.*FF-HSE body\\+trailer \\(52 byte\\(s\\), from Message Length/Options\\) exceeds the 20 byte\\(s\\) actually available in this PDU -- truncated by 32 byte\\(s\\).*FDA Open Session Req body is 20 byte\\(s\\), expected at least 52 -- not decoded, shown as raw hex")

# Unexpected port: an otherwise perfectly valid SM Identify Req on a port that is none of the 4
# configured FF-HSE ports -- still decodes, but with the "not a configured/standard FF-HSE port"
# note (matches HART-IP's/BACnet's own posture: port is an annotation, never a detection gate).
add_test(NAME ffhse_unexpected_port_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_unexpected_port_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"SM Identify Req\",.*seen on UDP port 52200->40000, which is not a configured/standard FF-HSE port \\(1089/1090/1091/3622\\)")

# FF-HSE over TCP: the same 4 ports serve both transports -- a genuine FMS Initiate
# request/response round trip.
add_test(NAME ffhse_tcp_round_trip
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_tcp_round_trip PROPERTIES
  PASS_REGULAR_EXPRESSION "\"src_port\": 52300,.*\"protocol\": \"ffhse\",.*\"ffhse_message_name\": \"FMS Initiate Req\",.*\"dst_port\": 52300,.*\"ffhse_message_name\": \"FMS Initiate Rsp\"")

# One FDA Open Session Req PDU split across TWO TCP segments -- exercises
# ffhse_declared_length-driven cross-segment reassembly (mirrors hartip_declared_length's own
# TCP reassembly test): the first segment alone must show "buffering", not a wrong decode, and
# the reassembled PDU must decode correctly once the second segment arrives.
add_test(NAME ffhse_tcp_segment_split_reassembly
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format text)
set_tests_properties(ffhse_tcp_segment_split_reassembly PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[tcp\\]  buffering a FF-HSE PDU PDU/frame split across TCP segments 52310->1090: 20 of 64 declared byte\\(s\\) seen so far across 1 segment\\(s\\) on this flow, waiting for more.*\\[ffhse\\]  FDA Open Session Req \\[session-index=1 \\+7 more\\]\n *note: reassembled a FF-HSE PDU PDU/frame from 64 byte\\(s\\) spanning 2 TCP segments on this flow")

# Two SM Clear Assignment Info Rsp messages coalesced into ONE TCP segment (sender/OS coalescing)
# -- exercises the wire_length-driven "additional FF-HSE message" loop for TCP.
add_test(NAME ffhse_tcp_coalesced_pdus
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --format json)
set_tests_properties(ffhse_tcp_coalesced_pdus PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ffhse_message_name\": \"SM Clear Assignment Info Rsp\",.*additional FF-HSE PDU 2 found in the same TCP payload at byte offset 12 \\(coalesced by the sender/OS\\): SM Clear Assignment Info Rsp")

# --stats accumulation: sub-protocol counts, per-message counts, and the Tier-1-decoded total.
add_test(NAME stats_mode_ffhse
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --stats)
set_tests_properties(stats_mode_ffhse PROPERTIES
  PASS_REGULAR_EXPRESSION "ffhse sub-protocols:.*FDA Session Management.*FMS.*LAN Redundancy.*SM.*ffhse messages:.*ffhse message bodies fully decoded \\(Tier 1\\): [0-9]+")

# ---------------------------------------------------------------------------------------------
# DNS / mDNS / LLMNR / NetBIOS Name Service (NBT-NS) decoding, and DNS-over-HTTPS detection --
# see dns.hpp/nbns.hpp/tls_sni.hpp's own file header comments. Fixtures generated by
# tools/make_sample_pcap.py's build_dns_sample()/build_mdns_sample()/build_llmnr_sample()/
# build_nbns_sample()/build_doh_sample().
# ---------------------------------------------------------------------------------------------

add_test(NAME dns_a_query_and_response
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dns.pcap" --format json)
set_tests_properties(dns_a_query_and_response PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"dns\",.*\"dns_records\": \\[\"question: plc01.plant.example A IN\"\\].*\"dns_records\": \\[\"question: plc01.plant.example A IN\", \"answer: plc01.plant.example A IN ttl=300s -> address=192.168.1.10\"\\]")

add_test(NAME dns_aaaa_cname_soa_mx_txt_srv_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dns.pcap" --format json)
set_tests_properties(dns_aaaa_cname_soa_mx_txt_srv_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "address=2001:db8:0:0:0:0:0:a.*cname=hmi.plant.example.*preference=10 exchange=mail.plant.example.*txt\\[0\\]=v=spf1 -all.*mname=ns1.plant.example rname=hostmaster.plant.example serial=2024010101.*priority=0 weight=100 port=389 target=dc01.plant.example")

add_test(NAME dns_nxdomain_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dns.pcap" --format text)
set_tests_properties(dns_nxdomain_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "DNS response id=0x1234 Query NXDomain \\[RD,RA\\], 1 question\\(s\\), 0 answer\\(s\\)")

add_test(NAME dns_opt_pseudo_record_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dns.pcap" --format json)
set_tests_properties(dns_opt_pseudo_record_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "additional: . OPT udp-payload-size=4096 extended-rcode=0 version=0 DO")

add_test(NAME dns_truncated_record_count_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dns.pcap" --format text)
set_tests_properties(dns_truncated_record_count_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "stopped parsing the answer section after 1 of 5 declared record\\(s\\) -- truncated or malformed")

add_test(NAME dns_non_dns_shaped_udp53_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dns.pcap" --format text)
set_tests_properties(dns_non_dns_shaped_udp53_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 6 byte\\(s\\) on port 53500->53")

add_test(NAME mdns_qu_bit_and_cache_flush_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mdns.pcap" --format json)
set_tests_properties(mdns_qu_bit_and_cache_flush_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"mdns\",.*\"dns_records\": \\[\"question: plc01.local A IN \\(QU\\)\"\\].*\"dns_records\": \\[\"answer: plc01.local A IN ttl=120s \\(cache-flush\\) -> address=192.168.1.10\"\\]")

add_test(NAME mdns_dns_sd_ptr_srv_txt_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mdns.pcap" --format json)
set_tests_properties(mdns_dns_sd_ptr_srv_txt_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "ptrdname=PLC01._http._tcp.local.*priority=0 weight=0 port=80 target=plc01.local.*txt\\[0\\]=path=/status")

add_test(NAME llmnr_conflict_bit_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_llmnr.pcap" --format text)
set_tests_properties(llmnr_conflict_bit_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[llmnr\\]  LLMNR response id=0x1234 Query NoError \\[C\\], 1 question\\(s\\), 1 answer\\(s\\).*-- dupe-host")

add_test(NAME llmnr_nonzero_reserved_bits_rejects_detection
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_llmnr.pcap" --format text)
set_tests_properties(llmnr_nonzero_reserved_bits_rejects_detection PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 21 byte\\(s\\) on port 5355->5355")

add_test(NAME nbns_nb_positive_response_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_nbns.pcap" --format json)
set_tests_properties(nbns_nb_positive_response_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"nbns\",.*\"nbns_records\": \\[\"answer: PLC01<00> \\(Workstation Service\\) NB ttl=300000s -> 192.168.1.10 \\(unique, B-node\\)\"\\]")

add_test(NAME nbns_nbstat_name_table_and_mac_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_nbns.pcap" --format json)
set_tests_properties(nbns_nbstat_name_table_and_mac_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "PLC01<00> \\(Workstation Service\\) unique ACT PRM.*PLC01<20> \\(File Server Service\\) unique ACT PRM.*PLANT<1C> \\(Domain Controllers\\) group ACT.*unit_id=00:0C:29:AA:BB:CC")

add_test(NAME nbns_malformed_name_length_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_nbns.pcap" --format text)
set_tests_properties(nbns_malformed_name_length_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 29 byte\\(s\\) on port 137->137")

add_test(NAME doh_known_resolver_sni_detected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_doh.pcap" --format json)
set_tests_properties(doh_known_resolver_sni_detected PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"doh\",.*\"doh_sni\": \"cloudflare-dns.com\",.*\"doh_matched_provider\": \"Cloudflare DNS\",.*\"doh_alpn_protocols\": \\[\"h2\", \"http/1.1\"\\]")

add_test(NAME doh_provider_suffix_match_nextdns
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_doh.pcap" --format json)
set_tests_properties(doh_provider_suffix_match_nextdns PROPERTIES
  PASS_REGULAR_EXPRESSION "\"doh_sni\": \"abc123.dns.nextdns.io\",.*\"doh_matched_provider\": \"NextDNS\"")

add_test(NAME doh_unrelated_https_sni_not_flagged
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_doh.pcap" --format text)
set_tests_properties(doh_unrelated_https_sni_not_flagged PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[tcp\\]  TCP payload of 76 byte\\(s\\) on port 54001->443 did not match")

add_test(NAME doh_non_tls_tcp443_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_doh.pcap" --format text)
set_tests_properties(doh_non_tls_tcp443_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[tcp\\]  TCP payload of 8 byte\\(s\\) on port 54003->443 did not match")

add_test(NAME protocol_filter_dns_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dns.pcap" --protocol dns --format text)
set_tests_properties(protocol_filter_dns_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[dns\\]  DNS query")

add_test(NAME stats_mode_dns_family_and_nbns_and_doh
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dns.pcap" --stats)
set_tests_properties(stats_mode_dns_family_and_nbns_and_doh PROPERTIES
  PASS_REGULAR_EXPRESSION "dns/mdns/llmnr opcodes:.*dns Query")

# ---------------------------------------------------------------------------------------------
# RIP / IGMP / VRRP / HSRP decoding -- see rip.hpp/igmp.hpp/vrrp.hpp/hsrp.hpp's own file header
# comments. Fixtures generated by tools/make_sample_pcap.py's build_rip_sample()/
# build_igmp_sample()/build_vrrp_sample()/build_hsrp_sample().
# ---------------------------------------------------------------------------------------------

add_test(NAME rip_full_table_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_rip.pcap" --format text)
set_tests_properties(rip_full_table_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[rip\\]  RIPv2 Request: full routing table requested")

add_test(NAME rip_ordinary_routes_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_rip.pcap" --format json)
set_tests_properties(rip_ordinary_routes_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"rip\",.*\"rip_command\": \"Response\",.*\"rip_routes\": \\[\"10.0.0.0/255.255.255.0 via 0.0.0.0 metric 1\", \"10.0.1.0/255.255.255.0 via 0.0.0.0 metric 2 tag 5\"\\]")

add_test(NAME rip_simple_password_auth_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_rip.pcap" --format json)
set_tests_properties(rip_simple_password_auth_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"rip_routes\": \\[\"authentication: Simple Password\", \"10.0.2.0/255.255.255.0 via 0.0.0.0 metric 3\"\\].*RIPv2 Simple Password authentication \\(auth_type 2\\) sends this password in cleartext on the wire")

add_test(NAME rip_md5_auth_trailing_digest_not_verified
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_rip.pcap" --format json)
set_tests_properties(rip_md5_auth_trailing_digest_not_verified PROPERTIES
  PASS_REGULAR_EXPRESSION "\"rip_routes\": \\[\"authentication: Keyed Message Digest \\(MD5\\) \\(key id 1\\)\", \"10.0.3.0/255.255.255.0 via 0.0.0.0 metric 4\"\\].*16 trailing byte\\(s\\) after the last complete route table entry do not form a full 20-byte RTE")

add_test(NAME rip_v1_nonconformant_route_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_rip.pcap" --format text)
set_tests_properties(rip_v1_nonconformant_route_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: route to 10.0.5.0 declares version 1 but has a nonzero Route Tag/Subnet Mask/Next Hop field \\(those are RIPv2-only\\) -- possible mislabeled RIPv2 traffic or a nonconformant sender")

add_test(NAME rip_invalid_command_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_rip.pcap" --format text)
set_tests_properties(rip_invalid_command_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 24 byte\\(s\\) on port 520->520")

add_test(NAME protocol_filter_rip_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_rip.pcap" --protocol rip --format text)
set_tests_properties(protocol_filter_rip_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[rip\\]  RIPv2 Request")

add_test(NAME stats_mode_rip
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_rip.pcap" --stats)
set_tests_properties(stats_mode_rip PROPERTIES
  PASS_REGULAR_EXPRESSION "rip commands:.*Request .*1\n.*Response .*6")

add_test(NAME igmp_v1_query_and_report_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igmp.pcap" --format text)
set_tests_properties(igmp_v1_query_and_report_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[igmp\\]  IGMPv1 Membership Query: group 0.0.0.0 \\(general query\\).*\\[igmp\\]  IGMPv1 Version 1 Membership Report: group 239.1.1.1")

add_test(NAME igmp_v2_query_report_leave_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igmp.pcap" --format text)
set_tests_properties(igmp_v2_query_report_leave_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "IGMPv2 Membership Query: group 239.1.1.1, max response time 10000 ms.*IGMPv2 Version 2 Membership Report: group 239.2.2.2.*IGMPv2 Version 2 Leave Group: group 239.2.2.2")

add_test(NAME igmp_v3_query_source_list_and_exponential_max_resp_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igmp.pcap" --format text)
set_tests_properties(igmp_v3_query_source_list_and_exponential_max_resp_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "IGMPv3 Membership Query: group 0.0.0.0 \\(general query\\), 2 source\\(s\\), max response time 22400 ms")

add_test(NAME igmp_v3_report_group_records_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igmp.pcap" --format json)
set_tests_properties(igmp_v3_report_group_records_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"igmp_group_records\": \\[\"Mode Is Include: 239.1.1.1 \\(2 source\\(s\\)\\)\", \"Mode Is Exclude: 239.2.2.2 \\(0 source\\(s\\)\\)\", \"Allow New Sources: 239.3.3.3 \\(1 source\\(s\\)\\)\"\\]")

add_test(NAME igmp_invalid_type_falls_back_to_non_tcp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igmp.pcap" --format text)
set_tests_properties(igmp_invalid_type_falls_back_to_non_tcp PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-tcp\\]  IPv4 protocol number 2 \\(IGMP\\) \\(not TCP\\)")

add_test(NAME protocol_filter_igmp_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igmp.pcap" --protocol igmp --format text)
set_tests_properties(protocol_filter_igmp_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[igmp\\]  IGMPv1 Membership Query")

add_test(NAME stats_mode_igmp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igmp.pcap" --stats)
set_tests_properties(stats_mode_igmp PROPERTIES
  PASS_REGULAR_EXPRESSION "igmp types:.*Membership Query")

# --------------------------------------------------------------------------
# Real-world IGMP capture -- see tests/real_captures/igmp/ATTRIBUTION.md for provenance (also
# documents why no real RIP/VRRP/HSRP capture could be found across the same 498-file search).
# --------------------------------------------------------------------------

# plant1_igmp_only.pcap: 12 real IGMPv3 Membership Reports from a single host, trimmed with
# `tshark -Y igmp -w` from the same Plant1.pcap this project's STP/PROFINET/CIP-I/O fixtures
# already draw from (see ATTRIBUTION.md). Every frame carries a genuine 4-byte IP Router Alert
# option (24-byte IP header) and Ethernet minimum-frame-size padding -- real-world exercises this
# decoder's synthetic fixture alone does not cover.
add_test(NAME real_igmp_plant1_does_not_crash
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/igmp/plant1_igmp_only.pcap")

add_test(NAME real_igmp_plant1_single_record_report_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/igmp/plant1_igmp_only.pcap" --format json)
set_tests_properties(real_igmp_plant1_single_record_report_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"igmp\",.*\"igmp_version\": 3,.*\"igmp_type\": \"Version 3 Membership Report\",.*\"igmp_group_records\": \\[\"Change To Exclude Mode: 224.0.0.252 \\(0 source\\(s\\)\\)\"\\]")

add_test(NAME real_igmp_plant1_two_record_report_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/igmp/plant1_igmp_only.pcap" --format json)
set_tests_properties(real_igmp_plant1_two_record_report_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"igmp_group_records\": \\[\"Change To Exclude Mode: 224.0.0.252 \\(0 source\\(s\\)\\)\", \"Change To Exclude Mode: 239.255.255.250 \\(0 source\\(s\\)\\)\"\\]")

add_test(NAME real_igmp_plant1_router_alert_padding_note_present
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/igmp/plant1_igmp_only.pcap" --format text)
set_tests_properties(real_igmp_plant1_router_alert_padding_note_present PROPERTIES
  PASS_REGULAR_EXPRESSION "note: 6 trailing byte\\(s\\) after the IP header's declared total length were trimmed")

add_test(NAME real_igmp_plant1_all_12_frames_decoded_as_igmp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/real_captures/igmp/plant1_igmp_only.pcap" --stats)
set_tests_properties(real_igmp_plant1_all_12_frames_decoded_as_igmp PROPERTIES
  PASS_REGULAR_EXPRESSION "packets: +12.*protocols:\n *igmp +12.*igmp types:\n *Version 3 Membership Report +12")

add_test(NAME vrrp_v2_advertisement_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vrrp.pcap" --format json)
set_tests_properties(vrrp_v2_advertisement_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"vrrp\",.*\"vrrp_version\": 2,.*\"vrrp_virtual_router_id\": 1,.*\"vrrp_priority\": 100,.*\"vrrp_ip_addresses\": \\[\"192.168.1.1\"\\]")

add_test(NAME vrrp_v2_simple_password_auth_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vrrp.pcap" --format text)
set_tests_properties(vrrp_v2_simple_password_auth_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: VRRPv2 Simple Text Password authentication \\(auth_type 1\\) sends this password in cleartext on the wire")

add_test(NAME vrrp_v2_priority_edge_cases_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vrrp.pcap" --format text)
set_tests_properties(vrrp_v2_priority_edge_cases_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "priority 255 \\(address owner\\), 2 virtual IP\\(s\\) \\(192.168.2.1, ...\\).*priority 0 \\(current master is stopping\\)")

add_test(NAME vrrp_v3_advertisement_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vrrp.pcap" --format text)
set_tests_properties(vrrp_v3_advertisement_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[vrrp\\]  VRRPv3 Advertisement: VRID 3, priority 100 \\(backup\\), 1 virtual IP\\(s\\) \\(192.168.3.1\\)")

add_test(NAME vrrp_invalid_type_falls_back_to_non_tcp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vrrp.pcap" --format text)
set_tests_properties(vrrp_invalid_type_falls_back_to_non_tcp PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-tcp\\]  IPv4 protocol number 112 \\(VRRP\\) \\(not TCP\\)")

add_test(NAME protocol_filter_vrrp_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vrrp.pcap" --protocol vrrp --format text)
set_tests_properties(protocol_filter_vrrp_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[vrrp\\]  VRRPv2 Advertisement")

add_test(NAME stats_mode_vrrp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vrrp.pcap" --stats)
set_tests_properties(stats_mode_vrrp PROPERTIES
  PASS_REGULAR_EXPRESSION "vrrp versions:.*VRRPv2 .*4\n.*VRRPv3 .*1")

add_test(NAME hsrp_v1_hello_coup_resign_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hsrp.pcap" --format text)
set_tests_properties(hsrp_v1_hello_coup_resign_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hsrp\\]  HSRPv1 Hello: group 1, state Active, priority 100, virtual IP 192.168.1.1.*\\[hsrp\\]  HSRPv1 Coup: group 1, state Speak, priority 110.*\\[hsrp\\]  HSRPv1 Resign: group 1, state Standby, priority 100")

add_test(NAME hsrp_v1_cleartext_auth_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hsrp.pcap" --format text)
set_tests_properties(hsrp_v1_cleartext_auth_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: HSRPv1 authentication is a cleartext plaintext field with no real security value")

add_test(NAME hsrp_v2_group_state_tlv_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hsrp.pcap" --format json)
set_tests_properties(hsrp_v2_group_state_tlv_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"hsrp\",.*\"hsrp_version\": 2,.*\"hsrp_tlv_types\": \\[\"Group State\"\\],.*\"hsrp_tlvs_truncated\": false")

# Regression test for a real collision found while adding this decoder: FF-HSE's own opportunistic,
# any-port structural gate is weak enough that it was accepting a synthetic HSRPv1 message on port
# 1985 as truncated FF-HSE traffic before RIP/HSRP were moved ahead of FF-HSE in decoder.cpp's UDP
# dispatch chain (see the comment there). This must decode as hsrp, never ffhse.
add_test(NAME hsrp_not_misdetected_as_ffhse
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hsrp.pcap" --format text)
set_tests_properties(hsrp_not_misdetected_as_ffhse PROPERTIES
  PASS_REGULAR_EXPRESSION "#1  .*\\[hsrp\\]  HSRPv1 Hello")

add_test(NAME hsrp_invalid_payload_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hsrp.pcap" --format text)
set_tests_properties(hsrp_invalid_payload_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[udp\\]  UDP payload of 5 byte\\(s\\) on port 1985->1985")

add_test(NAME protocol_filter_hsrp_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hsrp.pcap" --protocol hsrp --format text)
set_tests_properties(protocol_filter_hsrp_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[hsrp\\]  HSRPv1 Hello")

add_test(NAME stats_mode_hsrp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hsrp.pcap" --stats)
set_tests_properties(stats_mode_hsrp PROPERTIES
  PASS_REGULAR_EXPRESSION "hsrp versions:.*HSRPv1 .*3\n.*HSRPv2 .*1")

# ---------------------------------------------------------------------------------------------
# IGRP / PIM / EIGRP / OSPF decoding -- see igrp.hpp/pim.hpp/eigrp.hpp/ospf.hpp's own file header
# comments. Fixtures generated by tools/make_sample_pcap.py's build_igrp_sample()/
# build_pim_sample()/build_eigrp_sample()/build_ospf_sample(). BGP is deferred to a later round
# (it needs TCP port-179 stream reassembly, unlike these four IP-layer-only protocols).
# ---------------------------------------------------------------------------------------------

add_test(NAME igrp_response_and_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igrp.pcap" --format text)
set_tests_properties(igrp_response_and_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[igrp\\]  IGRP Response: AS 100, 2 interior / 1 system / 1 exterior route\\(s\\).*\\[igrp\\]  IGRP Request: AS 100, 0 interior / 0 system / 0 exterior route\\(s\\)")

add_test(NAME igrp_interior_route_address_reconstructed_from_source_ip
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igrp.pcap" --format json)
set_tests_properties(igrp_interior_route_address_reconstructed_from_source_ip PROPERTIES
  PASS_REGULAR_EXPRESSION "\"igrp_routes\": \\[\"Interior 192.168.5.0 delay=1000us bw=10000kbps hops=2\", \"Interior 192.168.6.0 unreachable\", \"System 10.0.0.0 delay=2000us bw=10000kbps hops=4\", \"Exterior 172.16.0.0 delay=3000us bw=20000kbps hops=6\"\\]")

add_test(NAME igrp_truncated_route_table_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igrp.pcap" --format text)
set_tests_properties(igrp_truncated_route_table_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: Interior\\+System\\+Exterior counts declare 50 route\\(s\\) but only 1 complete 14-byte route vector\\(s\\) are present")

add_test(NAME igrp_short_payload_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igrp.pcap" --format text)
set_tests_properties(igrp_short_payload_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-tcp\\]  IPv4 protocol number 9 \\(IGRP\\) \\(not TCP\\)")

add_test(NAME protocol_filter_igrp_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igrp.pcap" --protocol igrp --format text)
set_tests_properties(protocol_filter_igrp_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[igrp\\]  IGRP Response")

add_test(NAME stats_mode_igrp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_igrp.pcap" --stats)
set_tests_properties(stats_mode_igrp PROPERTIES
  PASS_REGULAR_EXPRESSION "igrp opcodes:.*Request .*1\n.*Response .*2")

add_test(NAME pim_hello_options_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --format json)
set_tests_properties(pim_hello_options_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"pim\",.*\"pim_type\": \"Hello\",.*\"pim_hello_options\": \\[\"Hold Time: 105s\", \"DR Priority: 1\", \"Generation ID: 305419896\", \"Address List \\(192.168.1.50\\)\"\\]")

add_test(NAME pim_register_inner_addresses_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --format text)
set_tests_properties(pim_register_inner_addresses_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[pim\\]  PIMv2 Register: \\(10.0.0.5, 239.1.1.1\\)")

add_test(NAME pim_register_stop_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --format text)
set_tests_properties(pim_register_stop_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[pim\\]  PIMv2 Register-Stop: group 239.1.1.1/32, source 10.0.0.5")

add_test(NAME pim_join_prune_groups_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --format json)
set_tests_properties(pim_join_prune_groups_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"pim_type\": \"Join/Prune\",.*\"pim_jp_upstream_neighbor\": \"192.168.1.10\",.*\"pim_jp_holdtime_sec\": 210,.*\"pim_jp_groups\": \\[\"239.1.1.1/32: 1 join\\(s\\), 1 prune\\(s\\)\"\\]")

add_test(NAME pim_bootstrap_candidate_rp_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --format text)
set_tests_properties(pim_bootstrap_candidate_rp_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[pim\\]  PIMv2 Bootstrap: BSR 192.168.1.50, 1 group\\(s\\)")

add_test(NAME pim_assert_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --format text)
set_tests_properties(pim_assert_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[pim\\]  PIMv2 Assert: group 239.1.1.1/32, source 10.0.0.5")

add_test(NAME pim_candidate_rp_advertisement_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --format text)
set_tests_properties(pim_candidate_rp_advertisement_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[pim\\]  PIMv2 Candidate-RP-Advertisement: RP 192.168.1.50, 1 group\\(s\\)")

add_test(NAME pim_invalid_type_falls_back_to_non_tcp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --format text)
set_tests_properties(pim_invalid_type_falls_back_to_non_tcp PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-tcp\\]  IPv4 protocol number 103 \\(PIM\\) \\(not TCP\\)")

add_test(NAME protocol_filter_pim_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --protocol pim --format text)
set_tests_properties(protocol_filter_pim_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[pim\\]  PIMv2 Hello")

add_test(NAME stats_mode_pim
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_pim.pcap" --stats)
set_tests_properties(stats_mode_pim PROPERTIES
  PASS_REGULAR_EXPRESSION "pim types:.*Assert .*1")

add_test(NAME eigrp_hello_and_ack_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_eigrp.pcap" --format text)
set_tests_properties(eigrp_hello_and_ack_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[eigrp\\]  EIGRP Hello: AS 100, 1 other TLV\\(s\\).*\\[eigrp\\]  EIGRP Hello \\(Ack\\): AS 100")

add_test(NAME eigrp_classic_route_with_compound_destinations_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_eigrp.pcap" --format json)
set_tests_properties(eigrp_classic_route_with_compound_destinations_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"eigrp_routes\": \\[\"Internal route: next-hop 10.0.0.1, 1 destination\\(s\\) \\(10.0.1.0/24\\)\", \"External route: next-hop 10.0.0.1, 2 destination\\(s\\) \\(192.168.10.0/24, ...\\)\"\\]")

add_test(NAME eigrp_wide_metric_route_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_eigrp.pcap" --format json)
set_tests_properties(eigrp_wide_metric_route_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"eigrp_routes\": \\[\"Internal route \\(wide metric\\): next-hop 10.0.0.1, 1 destination\\(s\\) \\(10.0.2.0/24\\)\", \"External route \\(wide metric\\): next-hop 10.0.0.1, 1 destination\\(s\\) \\(172.20.0.0/16\\)\"\\]")

add_test(NAME eigrp_general_tlvs_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_eigrp.pcap" --format json)
set_tests_properties(eigrp_general_tlvs_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"eigrp_general_tlvs\": \\[\"Authentication: MD5 \\(declared digest length 16 byte\\(s\\), not verified\\)\", \"Sequence: 1 IPv4 peer address\\(es\\): 192.168.1.50\", \"Software Version: EIGRP=15.2, TLV=3.0\"\\]")

add_test(NAME eigrp_short_payload_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_eigrp.pcap" --format text)
set_tests_properties(eigrp_short_payload_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-tcp\\]  IPv4 protocol number 88 \\(EIGRP\\) \\(not TCP\\)")

add_test(NAME protocol_filter_eigrp_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_eigrp.pcap" --protocol eigrp --format text)
set_tests_properties(protocol_filter_eigrp_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[eigrp\\]  EIGRP Hello")

add_test(NAME stats_mode_eigrp
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_eigrp.pcap" --stats)
set_tests_properties(stats_mode_eigrp PROPERTIES
  PASS_REGULAR_EXPRESSION "eigrp opcodes:.*Hello .*1\n.*Hello \\(Ack\\) .*1\n.*Update .*2")

add_test(NAME ospf_hello_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ospf.pcap" --format json)
set_tests_properties(ospf_hello_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"protocol\": \"ospf\",.*\"ospf_type\": \"Hello\",.*\"ospf_hello_designated_router\": \"10.0.0.1\",.*\"ospf_hello_backup_designated_router\": \"0.0.0.0\",.*\"ospf_hello_neighbors\": \\[\"10.0.0.2\"\\]")

add_test(NAME ospf_dbd_simple_password_auth_and_lsa_headers_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ospf.pcap" --format json)
set_tests_properties(ospf_dbd_simple_password_auth_and_lsa_headers_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ospf_type\": \"DB Description\",.*\"ospf_auth_type\": \"Simple password\",.*\"ospf_dbd_lsa_headers\": \\[\"Router len 44: 10.0.0.1 10.0.0.1 Seq=0x80000001 Age=100s\", \"Network len 28: 10.0.0.0 10.0.0.2 Seq=0x80000001 Age=200s\"\\].*AuType 1 \\(Simple password\\) sends this password in cleartext on the wire")

add_test(NAME ospf_ls_request_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ospf.pcap" --format text)
set_tests_properties(ospf_ls_request_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[ospf\\]  OSPFv2 LS Request: Router 10.0.0.1, Area 0.0.0.0, 2 request\\(s\\)")

add_test(NAME ospf_ls_update_lsa_bodies_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ospf.pcap" --format json)
set_tests_properties(ospf_ls_update_lsa_bodies_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\"ospf_auth_type\": \"Cryptographic\",.*\"ospf_ls_update_lsas\": \\[\"Router len 36: 10.0.0.1 10.0.0.1 Seq=0x80000002 Age=50s links=1 ABR\", \"Network len 32: 10.0.0.0 10.0.0.2 Seq=0x80000001 Age=60s \\(DoNotAge\\) mask=255.255.255.0 routers=2\", \"Summary len 28: 10.0.3.0 10.0.0.1 Seq=0x80000001 Age=70s mask=255.255.255.0 metric=20\", \"AS-External len 36: 10.0.4.0 10.0.0.1 Seq=0x80000001 Age=80s mask=255.255.255.0 metric=30 \\(Type 2\\)\"\\].*AuType 2 \\(Cryptographic/MD5\\) header fields decoded")

add_test(NAME ospf_ls_ack_decoded
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ospf.pcap" --format text)
set_tests_properties(ospf_ls_ack_decoded PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[ospf\\]  OSPFv2 LS Ack: Router 10.0.0.2, Area 0.0.0.0, 2 LSA header\\(s\\) acknowledged")

add_test(NAME ospf_v3_not_misdetected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ospf.pcap" --format text)
set_tests_properties(ospf_v3_not_misdetected PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[non-tcp\\]  IPv4 protocol number 89 \\(OSPF\\) \\(not TCP\\)")

add_test(NAME protocol_filter_ospf_only
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ospf.pcap" --protocol ospf --format text)
set_tests_properties(protocol_filter_ospf_only PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[ospf\\]  OSPFv2 Hello")

add_test(NAME stats_mode_ospf
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ospf.pcap" --stats)
set_tests_properties(stats_mode_ospf PROPERTIES
  PASS_REGULAR_EXPRESSION "ospf types:.*DB Description .*1")

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
# Resolver (resolver.hpp/resolver.cpp): OUI (MAC vendor) resolution (on by default, --no-oui),
# hostname resolution (off by default, --resolve/--hosts, file-only -- never live DNS), and
# service name resolution (on by default, --nn/--services) -- see decoder.cpp's src_mac/dst_mac
# gap-fix and output.cpp's TextWriter/JsonWriter/CsvWriter for how these are rendered. All tests
# below use tests/sample_modbus.pcap, whose two endpoints' MACs (00:0c:29:11:22:33/
# 00:0c:29:aa:bb:cc) are both in oui_table.gen.hpp's MA-L table as "VMware", and
# tests/hosts_sample.txt / tests/services_sample.txt (see their own file headers) as the
# --hosts/--services fixtures.
# ---------------------------------------------------------------------------------------------

set(RESOLVER_HOSTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/hosts_sample.txt")
set(RESOLVER_SERVICES "${CMAKE_CURRENT_SOURCE_DIR}/tests/services_sample.txt")

# --- OUI (MAC vendor), on by default --------------------------------------------------------

add_test(NAME resolver_oui_vendor_shown_by_default_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --format text)
set_tests_properties(resolver_oui_vendor_shown_by_default_text PROPERTIES
  PASS_REGULAR_EXPRESSION "eth 00:0c:29:11:22:33 \\(VMware\\) -> 00:0c:29:aa:bb:cc \\(VMware\\)")

add_test(NAME resolver_oui_vendor_shown_by_default_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --format json)
set_tests_properties(resolver_oui_vendor_shown_by_default_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"src_mac\": \"00:0c:29:11:22:33\",\n *\"dst_mac\": \"00:0c:29:aa:bb:cc\",\n *\"src_mac_vendor\": \"VMware\",\n *\"dst_mac_vendor\": \"VMware\",")

add_test(NAME resolver_no_oui_suppresses_vendor_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --no-oui --format text)
set_tests_properties(resolver_no_oui_suppresses_vendor_text PROPERTIES
  PASS_REGULAR_EXPRESSION "eth 00:0c:29:11:22:33 -> 00:0c:29:aa:bb:cc\n"
  FAIL_REGULAR_EXPRESSION "VMware")

add_test(NAME resolver_no_oui_suppresses_vendor_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --no-oui --format json)
set_tests_properties(resolver_no_oui_suppresses_vendor_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"src_mac\": \"00:0c:29:11:22:33\","
  FAIL_REGULAR_EXPRESSION "_mac_vendor")

# src_mac/dst_mac themselves (the base gap-fix, independent of OUI resolution) are always present
# for an Ethernet-linktype capture, even with --no-oui -- this is the actual base value, not an
# annotation, so --no-oui only ever suppresses the vendor name, never the MAC itself.
add_test(NAME resolver_base_src_dst_mac_always_present_regardless_of_no_oui
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --no-oui --format csv)
set_tests_properties(resolver_base_src_dst_mac_always_present_regardless_of_no_oui PROPERTIES
  PASS_REGULAR_EXPRESSION "00:0c:29:11:22:33,00:0c:29:aa:bb:cc,,,")

# --- Hostname resolution, off by default, file-only ------------------------------------------

add_test(NAME resolver_hostname_off_by_default
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --format text)
set_tests_properties(resolver_hostname_off_by_default PROPERTIES
  FAIL_REGULAR_EXPRESSION "hmi-01|plc-01")

add_test(NAME resolver_resolve_with_no_hosts_file_is_a_harmless_noop
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --resolve --format text)
set_tests_properties(resolver_resolve_with_no_hosts_file_is_a_harmless_noop PROPERTIES
  PASS_REGULAR_EXPRESSION "note: --resolve was given with no --hosts file; hostname resolution has nothing to resolve against"
  FAIL_REGULAR_EXPRESSION "hmi-01|plc-01|error:")

add_test(NAME resolver_resolve_with_no_hosts_file_noop_note_respects_quiet
  COMMAND conduitscope --quiet decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --resolve --format text)
set_tests_properties(resolver_resolve_with_no_hosts_file_noop_note_respects_quiet PROPERTIES
  FAIL_REGULAR_EXPRESSION "note: --resolve")

add_test(NAME resolver_resolve_with_hosts_file_annotates_matching_ips_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --resolve --hosts "${RESOLVER_HOSTS}" --format text)
set_tests_properties(resolver_resolve_with_hosts_file_annotates_matching_ips_text PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50 \\(hmi-01\\):51000 -> 192.168.1.10 \\(plc-01\\):502")

add_test(NAME resolver_resolve_with_hosts_file_annotates_matching_ips_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --resolve --hosts "${RESOLVER_HOSTS}" --format json)
set_tests_properties(resolver_resolve_with_hosts_file_annotates_matching_ips_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"src_hostname\": \"hmi-01\",\n *\"dst_hostname\": \"plc-01\",")

# tests/sample_modbus.pcap's own two addresses are the only ones hosts_sample.txt names; no other
# IP appears in this capture, so a positive "hostname resolution finds nothing when nothing
# matches" case is instead covered directly against Resolver's own file-parsing rules by the two
# duplicate-IP/first-wins fixture lines in hosts_sample.txt (see its own file header) -- exercised
# implicitly by the assertion above ("plc-01", not "should-never-win", for 192.168.1.10).
add_test(NAME resolver_hosts_file_first_occurrence_wins_not_last
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --resolve --hosts "${RESOLVER_HOSTS}" --format text)
set_tests_properties(resolver_hosts_file_first_occurrence_wins_not_last PROPERTIES
  FAIL_REGULAR_EXPRESSION "should-never-win")

# --- Service name resolution, on by default ---------------------------------------------------

add_test(NAME resolver_service_name_shown_by_default_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --format text)
set_tests_properties(resolver_service_name_shown_by_default_text PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.10:502 \\(modbus\\)")

add_test(NAME resolver_service_name_shown_by_default_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --format json)
set_tests_properties(resolver_service_name_shown_by_default_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"dst_port_service\": \"modbus\"")

add_test(NAME resolver_nn_suppresses_service_name_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --nn --format text)
set_tests_properties(resolver_nn_suppresses_service_name_text PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.10:502  \\[modbus\\]"
  FAIL_REGULAR_EXPRESSION "\\(modbus\\)")

add_test(NAME resolver_nn_suppresses_service_name_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --nn --format json)
set_tests_properties(resolver_nn_suppresses_service_name_json PROPERTIES
  FAIL_REGULAR_EXPRESSION "_port_service")

# --nn only disables service names -- OUI vendor annotations (an independent, still-default-on
# lookup) must still appear.
add_test(NAME resolver_nn_does_not_affect_oui
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --nn --format text)
set_tests_properties(resolver_nn_does_not_affect_oui PROPERTIES
  PASS_REGULAR_EXPRESSION "eth 00:0c:29:11:22:33 \\(VMware\\)")

add_test(NAME resolver_services_file_overrides_and_supplements_builtin_table_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --services "${RESOLVER_SERVICES}" --format text)
set_tests_properties(resolver_services_file_overrides_and_supplements_builtin_table_text PROPERTIES
  # 502/tcp: overridden from the built-in "modbus" to "custom-modbus". 51000/tcp: not in the
  # built-in table at all, supplemented by the file as "hmi-modbus-client".
  PASS_REGULAR_EXPRESSION "192.168.1.50:51000 \\(hmi-modbus-client\\) -> 192.168.1.10:502 \\(custom-modbus\\)"
  FAIL_REGULAR_EXPRESSION "\\(modbus\\)")

add_test(NAME resolver_services_file_overrides_and_supplements_builtin_table_csv
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --services "${RESOLVER_SERVICES}" --format csv)
set_tests_properties(resolver_services_file_overrides_and_supplements_builtin_table_csv PROPERTIES
  PASS_REGULAR_EXPRESSION "51000,hmi-modbus-client,192.168.1.10,,502,custom-modbus")

add_test(NAME resolver_services_given_with_nn_is_unused_and_noted
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --nn --services "${RESOLVER_SERVICES}" --format text)
set_tests_properties(resolver_services_given_with_nn_is_unused_and_noted PROPERTIES
  PASS_REGULAR_EXPRESSION "note: --services was given while --nn disables service name resolution"
  FAIL_REGULAR_EXPRESSION "custom-modbus|hmi-modbus-client")

# --- Combined: every resolution enabled at once, across all three formats --------------------

add_test(NAME resolver_all_enabled_together_text
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --resolve --hosts "${RESOLVER_HOSTS}" --services "${RESOLVER_SERVICES}" --format text)
set_tests_properties(resolver_all_enabled_together_text PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50 \\(hmi-01\\):51000 \\(hmi-modbus-client\\) -> 192.168.1.10 \\(plc-01\\):502 \\(custom-modbus\\)")

add_test(NAME resolver_all_enabled_together_json
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --resolve --hosts "${RESOLVER_HOSTS}" --services "${RESOLVER_SERVICES}" --format json)
set_tests_properties(resolver_all_enabled_together_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"src_mac_vendor\": \"VMware\",.*\"src_hostname\": \"hmi-01\",.*\"dst_hostname\": \"plc-01\",.*\"src_port_service\": \"hmi-modbus-client\",.*\"dst_port_service\": \"custom-modbus\"")

# --- Bad --hosts/--services paths rejected cleanly at CLI-parse time (CLI::ExistingFile) -----

add_test(NAME resolver_bad_hosts_path_rejected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --resolve --hosts "${CMAKE_CURRENT_SOURCE_DIR}/tests/does_not_exist_hosts.txt")
set_tests_properties(resolver_bad_hosts_path_rejected PROPERTIES
  WILL_FAIL TRUE)

add_test(NAME resolver_bad_services_path_rejected
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --services "${CMAKE_CURRENT_SOURCE_DIR}/tests/does_not_exist_services.txt")
set_tests_properties(resolver_bad_services_path_rejected PROPERTIES
  WILL_FAIL TRUE)

# --------------------------------------------------------------------------------------------
# Gap fix (a necessary, deliberate part of this feature, not scope creep -- see resolver.hpp's
# file header and docs/MANUAL.md): src_mac/dst_mac are now rendered for EVERY protocol on an
# Ethernet-linktype capture, not just the raw-Ethernet ones (GOOSE/SV/EtherCAT/PROFINET/STP) whose
# own MAC-bearing fields (stp_root_mac/etc.) were already shown. sample_enip.pcap is a plain
# IPv4-based protocol (EtherNet/IP explicit messaging over TCP) that never had any MAC output at
# all before this feature.
# --------------------------------------------------------------------------------------------

add_test(NAME resolver_mac_shown_for_plain_ip_protocol_not_just_raw_ethernet
  COMMAND conduitscope decode --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_enip.pcap" --format text)
set_tests_properties(resolver_mac_shown_for_plain_ip_protocol_not_just_raw_ethernet PROPERTIES
  PASS_REGULAR_EXPRESSION "\\[enip\\].*\n *eth 00:0c:29:11:22:33 \\(VMware\\) -> 00:0c:29:aa:bb:cc \\(VMware\\)")

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

add_test(NAME policy_multi_from_zones_matches_non_first_entry
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/multi_from_zones.yaml")
set_tests_properties(policy_multi_from_zones_matches_non_first_entry PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"corp or HMI reaches PLC via Modbus\"")

add_test(NAME policy_multi_to_zones_matches_non_first_entry
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/multi_to_zones.yaml")
set_tests_properties(policy_multi_to_zones_matches_non_first_entry PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"HMI reaches DMZ or PLC via Modbus\"")

add_test(NAME policy_multi_zone_bidirectional_reverse_match
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/multi_zone_bidirectional.yaml")
set_tests_properties(policy_multi_zone_bidirectional_reverse_match PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"PLC-side pushes to HMI-side")

add_test(NAME policy_json_multi_zone_conduit
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/multi_from_zones.yaml" --format json)
set_tests_properties(policy_json_multi_zone_conduit PROPERTIES
  PASS_REGULAR_EXPRESSION "\"from\": \\[\"corp_zone\", \"hmi_zone\"\\][^}]*\"to\": \\[\"plc_zone\"\\]")

add_test(NAME policy_error_unknown_zone_in_list
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_unknown_zone_in_list.yaml")
set_tests_properties(policy_error_unknown_zone_in_list PROPERTIES
  PASS_REGULAR_EXPRESSION "'from' zone 'nonexistent_zone' is not declared in 'zones'")

add_test(NAME policy_error_empty_from_list
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_empty_from_list.yaml")
set_tests_properties(policy_error_empty_from_list PROPERTIES
  PASS_REGULAR_EXPRESSION "conduit 'c1' declares no 'from' zones")

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
  PASS_REGULAR_EXPRESSION "no recognized OT protocol traffic was found on this flow \\(2 unrecognized/handshake packet\\(s\\) only\\)")

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
# 'functions:' allow-list (policy.hpp/policy_engine.cpp) -- restricts WHICH function/service
# within an already-permitted protocol a conduit allows. Fixtures: tests/policies/functions_*.yaml
# (one per protocol) and tests/policies/bad_functions_*.yaml (load-time validation errors). See
# each fixture's own header comment for exactly what it's testing.
# ---------------------------------------------------------------------------------------------

add_test(NAME policy_functions_modbus_restricted
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_pairing.pcap" --policy "${POLICY_DIR}/functions_modbus.yaml")
set_tests_properties(policy_functions_modbus_restricted PROPERTIES
  PASS_REGULAR_EXPRESSION "matched conduit \"modbus reads only\".*function 'Write Single Register' observed; conduit 'modbus reads only' permits only: Read Holding Registers")

add_test(NAME policy_functions_modbus_json_observed_functions
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus_pairing.pcap" --policy "${POLICY_DIR}/functions_modbus.yaml" --format json)
set_tests_properties(policy_functions_modbus_json_observed_functions PROPERTIES
  PASS_REGULAR_EXPRESSION "\"conduits\": \\[.*\"functions\": \\[\"Read Holding Registers\"\\].*\"observed_functions\": \\[\"Write Single Register\"\\]")

add_test(NAME policy_functions_dnp3_restricted
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --policy "${POLICY_DIR}/functions_dnp3.yaml")
set_tests_properties(policy_functions_dnp3_restricted PROPERTIES
  PASS_REGULAR_EXPRESSION "matched conduit \"dnp3 direct operate only\".*functions 'Read', 'Response' observed; conduit 'dnp3 direct operate only' permits only: Direct Operate")

add_test(NAME policy_functions_s7comm_compliant
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm_items.pcap" --policy "${POLICY_DIR}/functions_s7comm.yaml")
set_tests_properties(policy_functions_s7comm_compliant PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"s7comm read var only\"")

add_test(NAME policy_functions_s7comm_violation
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_s7comm.pcap" --policy "${POLICY_DIR}/functions_s7comm.yaml")
set_tests_properties(policy_functions_s7comm_violation PROPERTIES
  PASS_REGULAR_EXPRESSION "functions 'Setup Communication', 'Write Var' observed; conduit 's7comm read var only' permits only: Read Var")

add_test(NAME policy_functions_iec104_compliant
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104_modbus_precedence.pcap" --policy "${POLICY_DIR}/functions_iec104.yaml")
set_tests_properties(policy_functions_iec104_compliant PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"iec104 interrogation only\"")

add_test(NAME policy_functions_iec104_violation
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_iec104.pcap" --policy "${POLICY_DIR}/functions_iec104.yaml")
set_tests_properties(policy_functions_iec104_violation PROPERTIES
  PASS_REGULAR_EXPRESSION "functions 'C_DC_NA_1', 'M_ME_TD_1', 'M_SP_NA_1' observed; conduit 'iec104 interrogation only' permits only: C_IC_NA_1")

add_test(NAME policy_functions_enip_restricted
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_policy_functions_enip.pcap" --policy "${POLICY_DIR}/functions_enip.yaml")
set_tests_properties(policy_functions_enip_restricted PROPERTIES
  PASS_REGULAR_EXPRESSION "matched conduit \"enip read tag only\".*function 'Write_Tag' observed; conduit 'enip read tag only' permits only: Read_Tag")

add_test(NAME policy_functions_singular_alias
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/functions_singular_alias.yaml")
set_tests_properties(policy_functions_singular_alias PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"singular protocol/function alias\"")

add_test(NAME policy_functions_case_insensitive_match
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/functions_case_insensitive.yaml")
set_tests_properties(policy_functions_case_insensitive_match PROPERTIES
  PASS_REGULAR_EXPRESSION "Result: COMPLIANT.*matched conduit \"case-insensitive function match\"")

add_test(NAME policy_error_functions_multi_protocol_rejected
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_functions_multi_protocol.yaml")
set_tests_properties(policy_error_functions_multi_protocol_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "'functions' requires exactly one protocol in 'protocols' \\(not 'any', and not a list of more than one\\)")

add_test(NAME policy_error_functions_any_protocol_rejected
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_functions_any_protocol.yaml")
set_tests_properties(policy_error_functions_any_protocol_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "'functions' requires exactly one protocol in 'protocols' \\(not 'any', and not a list of more than one\\)")

add_test(NAME policy_error_functions_unknown_name_no_suggestion
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_functions_unknown_name.yaml")
set_tests_properties(policy_error_functions_unknown_name_no_suggestion PROPERTIES
  PASS_REGULAR_EXPRESSION "unknown modbus function 'Totally Unrelated Nonsense Function'"
  FAIL_REGULAR_EXPRESSION "did you mean")

add_test(NAME policy_error_functions_unknown_name_with_suggestion
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_functions_typo.yaml")
set_tests_properties(policy_error_functions_unknown_name_with_suggestion PROPERTIES
  PASS_REGULAR_EXPRESSION "unknown modbus function 'Read Holding Registerss' -- did you mean 'Read Holding Registers'\\?")

# Regression guard: a conduit with 'functions' omitted entirely must behave exactly as before this
# feature existed -- already covered by every pre-existing policy_* test above (none of them use
# 'functions:'), so no new fixture is needed here; this comment just records that coverage exists.

# --------------------------------------------------------------------------
# Widened `protocols` enum (ROADMAP item 14): bacnet/hartip/opcua/mms/mqtt/ffhse, in addition to
# the original modbus/dnp3/s7comm/iec104/enip/any -- see tests/policies/widened_protocols.yaml's
# own header comment and policy.hpp's Conduit::protocols comment.
# --------------------------------------------------------------------------

add_test(NAME policy_widened_opcua_sample_matches_conduit
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --policy "${POLICY_DIR}/widened_protocols.yaml")
set_tests_properties(policy_widened_opcua_sample_matches_conduit PROPERTIES
  PASS_REGULAR_EXPRESSION "\\(opcua, [0-9]+ packet\\(s\\)\\)\n *zones: hmi_zone -> plc_zone, matched conduit \"HMI reaches PLC via OPC UA\"")

add_test(NAME policy_widened_mms_sample_matches_conduit
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mms.pcap" --policy "${POLICY_DIR}/widened_protocols.yaml")
set_tests_properties(policy_widened_mms_sample_matches_conduit PROPERTIES
  PASS_REGULAR_EXPRESSION "\\(mms, [0-9]+ packet\\(s\\)\\)\n *zones: hmi_zone -> plc_zone, matched conduit \"HMI reaches PLC via MMS\"")

add_test(NAME policy_widened_mqtt_sample_matches_conduit
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_mqtt.pcap" --policy "${POLICY_DIR}/widened_protocols.yaml")
set_tests_properties(policy_widened_mqtt_sample_matches_conduit PROPERTIES
  PASS_REGULAR_EXPRESSION "\\(mqtt, [0-9]+ packet\\(s\\)\\)\n *zones: hmi_zone -> plc_zone, matched conduit \"HMI reaches PLC via MQTT\"")

add_test(NAME policy_widened_hartip_sample_matches_conduit
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_hartip.pcap" --policy "${POLICY_DIR}/widened_protocols.yaml")
set_tests_properties(policy_widened_hartip_sample_matches_conduit PROPERTIES
  PASS_REGULAR_EXPRESSION "\\(hartip, [0-9]+ packet\\(s\\)\\)\n *zones: hmi_zone -> plc_zone, matched conduit \"HMI reaches PLC via HART-IP\"")

add_test(NAME policy_widened_ffhse_sample_matches_conduit
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_ffhse.pcap" --policy "${POLICY_DIR}/widened_protocols.yaml")
set_tests_properties(policy_widened_ffhse_sample_matches_conduit PROPERTIES
  PASS_REGULAR_EXPRESSION "\\(ffhse, [0-9]+ packet\\(s\\)\\)\n *zones: hmi_zone -> plc_zone, matched conduit \"HMI reaches PLC via FF-HSE\"")

# BACnet/IP is UDP-only in this decoder (see decoder.cpp) and `policy validate` only ever
# evaluates TCP flows -- so a "bacnet" conduit parses and validates fine (this policy file loads
# without error against every fixture) but can never actually be exercised. Read against
# sample_modbus.pcap (which has no BACnet traffic at all, real or otherwise) purely to confirm the
# conduit is accepted and simply never matched.
add_test(NAME policy_widened_bacnet_conduit_parses_but_never_exercised
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/widened_protocols.yaml")
set_tests_properties(policy_widened_bacnet_conduit_parses_but_never_exercised PROPERTIES
  PASS_REGULAR_EXPRESSION "Conduits never exercised by this capture \\(6\\):.*BACnet placeholder")

add_test(NAME policy_error_functions_unsupported_protocol_rejected
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_opcua.pcap" --policy "${POLICY_DIR}/bad_functions_unsupported_protocol.yaml")
set_tests_properties(policy_error_functions_unsupported_protocol_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "'functions' is not yet supported for protocol 'opcua' -- only modbus, dnp3, s7comm, iec104, and enip have a known function/service name table so far")

add_test(NAME policy_error_unknown_protocol_lists_full_widened_set
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_unknown_protocol.yaml")
set_tests_properties(policy_error_unknown_protocol_lists_full_widened_set PROPERTIES
  PASS_REGULAR_EXPRESSION "unknown protocol 'profibus' \\(expected one of: modbus, dnp3, s7comm, iec104, enip, bacnet, hartip, opcua, mms, mqtt, ffhse, profinet, goose, sv, ethercat, any\\)")

# --------------------------------------------------------------------------
# VLAN-membership-based conduit/zone model (ROADMAP item 15): an alternative to the IPv4-CIDR zone
# model for the four protocols with no IP layer at all (PROFINET RT, GOOSE, Sampled Values,
# EtherCAT) -- see policy.hpp's file header comment, PolicyEngine::observe's doc comment, and
# docs/MANUAL.md's POLICY FILE FORMAT section. Validation-error fixtures below reuse
# sample_modbus.pcap (any capture will do -- every one of these errors fires at policy-load time,
# before a single packet is ever decoded); the worked-example fixtures are matched against the
# dedicated tests/sample_vlan_zones.pcap (see build_vlan_zones_sample in tools/make_sample_pcap.py).
# --------------------------------------------------------------------------

add_test(NAME policy_error_vlan_zone_both_networks_and_vlans
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_zone_both_networks_and_vlans.yaml")
set_tests_properties(policy_error_vlan_zone_both_networks_and_vlans PROPERTIES
  PASS_REGULAR_EXPRESSION "zone 'confused_zone' declares both 'networks' and 'vlans' -- a zone is either an IPv4 zone or a VLAN zone, not both")

add_test(NAME policy_error_vlan_zone_neither_networks_nor_vlans
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_zone_neither_networks_nor_vlans.yaml")
set_tests_properties(policy_error_vlan_zone_neither_networks_nor_vlans PROPERTIES
  PASS_REGULAR_EXPRESSION "zone 'empty_zone' has no 'networks' or 'vlans' key")

add_test(NAME policy_error_vlan_id_out_of_range
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_vlan_id_out_of_range.yaml")
set_tests_properties(policy_error_vlan_id_out_of_range PROPERTIES
  PASS_REGULAR_EXPRESSION "zone 'ot_vlan': '4095' is not a valid VLAN ID \\(expected 1-4094 -- VID 0 is reserved for priority-tagged, non-VLAN-member frames and 4095 is reserved outright\\)")

add_test(NAME policy_error_vlan_overlap
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_vlan_overlap.yaml")
set_tests_properties(policy_error_vlan_overlap PROPERTIES
  PASS_REGULAR_EXPRESSION "zone 'ot_vlan' and zone 'scada_vlan' both claim VLAN 100 -- each VLAN must belong to at most one zone")

add_test(NAME policy_error_conduit_mixed_zone_kinds
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_conduit_mixed_zone_kinds.yaml")
set_tests_properties(policy_error_conduit_mixed_zone_kinds PROPERTIES
  PASS_REGULAR_EXPRESSION "conduit 'c1' mixes IPv4 zones and VLAN zones in its 'from'/'to' -- every zone a conduit references must be the same kind")

add_test(NAME policy_error_conduit_tcp_protocol_on_vlan_zone
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_conduit_tcp_protocol_on_vlan_zone.yaml")
set_tests_properties(policy_error_conduit_tcp_protocol_on_vlan_zone PROPERTIES
  PASS_REGULAR_EXPRESSION "conduit 'c1': protocol 'modbus' rides IPv4/TCP, not raw Ethernet, so it can never appear on a VLAN-zone conduit -- only profinet, goose, sv, ethercat, or 'any' can")

add_test(NAME policy_error_conduit_vlan_protocol_on_ip_zone
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_conduit_vlan_protocol_on_ip_zone.yaml")
set_tests_properties(policy_error_conduit_vlan_protocol_on_ip_zone PROPERTIES
  PASS_REGULAR_EXPRESSION "conduit 'c1': protocol 'goose' has no IP layer at all, so it can never appear on an IPv4-zone conduit -- declare a VLAN zone instead")

add_test(NAME policy_error_vlan_conduit_from_to_mismatch
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_vlan_conduit_from_to_mismatch.yaml")
set_tests_properties(policy_error_vlan_conduit_from_to_mismatch PROPERTIES
  PASS_REGULAR_EXPRESSION "conduit 'c1' is a VLAN-zone conduit; 'from' and 'to' must name the exact same VLAN zone\\(s\\) -- it permits its protocol\\(s\\) ON that VLAN zone, not a directional flow between two zones")

add_test(NAME policy_error_vlan_conduit_ports_rejected
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_vlan_conduit_ports.yaml")
set_tests_properties(policy_error_vlan_conduit_ports_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "conduit 'c1': 'ports' has no meaning on a VLAN-zone conduit -- profinet/goose/sv/ethercat have no TCP/UDP layer at all")

add_test(NAME policy_error_vlan_conduit_bidirectional_rejected
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_vlan_conduit_bidirectional.yaml")
set_tests_properties(policy_error_vlan_conduit_bidirectional_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "conduit 'c1': 'bidirectional' has no meaning on a VLAN-zone conduit -- there is no client/server session to reverse")

add_test(NAME policy_error_vlan_conduit_functions_rejected
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/bad_vlan_conduit_functions.yaml")
set_tests_properties(policy_error_vlan_conduit_functions_rejected PROPERTIES
  PASS_REGULAR_EXPRESSION "conduit 'c1': 'functions'/'function' has no meaning on a VLAN-zone conduit -- profinet/goose/sv/ethercat have no per-flow function/service name this engine tracks yet")

# sample_vlan_zones.pcap: four protocols tagged VLAN 100 (HMI_MAC<->PLC_MAC), a GOOSE flow tagged
# VLAN 200 on a distinct MAC pair, and an untagged EtherCAT flow on a third distinct MAC pair (see
# build_vlan_zones_sample's own comment in tools/make_sample_pcap.py).

add_test(NAME policy_vlan_zone_single_segment_allowed_and_unclassified
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vlan_zones.pcap" --policy "${POLICY_DIR}/vlan_zone_single_segment.yaml")
set_tests_properties(policy_vlan_zone_single_segment_allowed_and_unclassified PROPERTIES
  PASS_REGULAR_EXPRESSION "Ethernet flows evaluated: 6 \\(4 allowed, 0 violation\\(s\\), 2 unclassified\\).*no declared VLAN zone contains VLAN 200.*frame carries no 802.1Q VLAN tag at all")

add_test(NAME policy_vlan_zone_mixed_results_all_three_verdicts
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vlan_zones.pcap" --policy "${POLICY_DIR}/vlan_zone_mixed_results.yaml")
set_tests_properties(policy_vlan_zone_mixed_results_all_three_verdicts PROPERTIES
  PASS_REGULAR_EXPRESSION "Ethernet flows evaluated: 6 \\(4 allowed, 1 violation\\(s\\), 1 unclassified\\).*no conduit permits goose traffic on VLAN zone 'office_vlan'.*frame carries no 802.1Q VLAN tag at all.*Conduits never exercised by this capture \\(1\\):.*EtherCAT only on office_vlan")

add_test(NAME policy_vlan_zone_json_format
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vlan_zones.pcap" --policy "${POLICY_DIR}/vlan_zone_mixed_results.yaml" --format json)
set_tests_properties(policy_vlan_zone_json_format PROPERTIES
  PASS_REGULAR_EXPRESSION "\"is_vlan_conduit\": true.*\"ethernet_flows\": \\[.*\"has_vlan_tag\": true,\n *\"vlan_id\": 100,\n *\"vlan_zone\": \"ot_vlan\".*\"has_vlan_tag\": false,\n *\"vlan_id\": null,\n *\"vlan_zone\": \"unclassified\"")

# ---------------------------------------------------------------------------------------------
# Resolver, wired into `policy validate`'s report too (write_policy_report_text/
# write_policy_report_json in policy_engine.cpp) -- the same OUI/hostname/service-name
# annotations exercised earlier (see this file's own "Resolver" section, above the resolver_*
# `decode` tests) now applied to FlowReport's client_ip/server_ip/server_port (and its
# client_mac/server_mac base-value gap-fix) and EthernetFlowReport's mac_a/mac_b.
# `policy validate` takes the identical --no-oui/--resolve/--hosts/--nn/--services flags (see
# cli_main.cpp's policy_validate_cmd) against the same tests/hosts_sample.txt/
# tests/services_sample.txt fixtures used by `decode`'s own resolver tests (RESOLVER_HOSTS/
# RESOLVER_SERVICES, set once, above). resolver.hpp's file header previously documented this as
# an explicit ROADMAP follow-up, out of scope for the original `decode`-only feature -- this
# section is that follow-up.
# ---------------------------------------------------------------------------------------------

add_test(NAME policy_resolver_oui_vendor_shown_by_default_text
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_resolver_oui_vendor_shown_by_default_text PROPERTIES
  PASS_REGULAR_EXPRESSION "mac: 00:0c:29:11:22:33 \\(VMware\\) -> 00:0c:29:aa:bb:cc \\(VMware\\)")

add_test(NAME policy_resolver_oui_vendor_shown_by_default_json
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --format json)
set_tests_properties(policy_resolver_oui_vendor_shown_by_default_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"client_mac\": \"00:0c:29:11:22:33\",\n *\"server_mac\": \"00:0c:29:aa:bb:cc\",\n *\"client_mac_vendor\": \"VMware\",\n *\"server_mac_vendor\": \"VMware\",")

add_test(NAME policy_resolver_no_oui_suppresses_vendor_text
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --no-oui)
set_tests_properties(policy_resolver_no_oui_suppresses_vendor_text PROPERTIES
  PASS_REGULAR_EXPRESSION "mac: 00:0c:29:11:22:33 -> 00:0c:29:aa:bb:cc\n"
  FAIL_REGULAR_EXPRESSION "VMware")

# client_mac/server_mac themselves (the base gap-fix) stay present in JSON even with --no-oui --
# only the *_vendor annotation is suppressed, same "base value vs. annotation" distinction as
# decode's own resolver_base_src_dst_mac_always_present_regardless_of_no_oui test.
add_test(NAME policy_resolver_no_oui_suppresses_vendor_json
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --no-oui --format json)
set_tests_properties(policy_resolver_no_oui_suppresses_vendor_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"client_mac\": \"00:0c:29:11:22:33\","
  FAIL_REGULAR_EXPRESSION "_mac_vendor")

add_test(NAME policy_resolver_hostname_off_by_default
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_resolver_hostname_off_by_default PROPERTIES
  FAIL_REGULAR_EXPRESSION "hmi-01|plc-01")

add_test(NAME policy_resolver_resolve_with_hosts_file_annotates_text
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --resolve --hosts "${RESOLVER_HOSTS}")
set_tests_properties(policy_resolver_resolve_with_hosts_file_annotates_text PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50 \\(hmi-01\\) -> 192.168.1.10 \\(plc-01\\):502")

add_test(NAME policy_resolver_resolve_with_hosts_file_annotates_json
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --resolve --hosts "${RESOLVER_HOSTS}" --format json)
set_tests_properties(policy_resolver_resolve_with_hosts_file_annotates_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"client_hostname\": \"hmi-01\",\n *\"server_hostname\": \"plc-01\",")

add_test(NAME policy_resolver_service_name_shown_by_default_text
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml")
set_tests_properties(policy_resolver_service_name_shown_by_default_text PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.10:502 \\(modbus\\)")

add_test(NAME policy_resolver_nn_suppresses_service_name_text
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --nn)
set_tests_properties(policy_resolver_nn_suppresses_service_name_text PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.10:502  \\("
  FAIL_REGULAR_EXPRESSION "502 \\(modbus\\)")

add_test(NAME policy_resolver_nn_suppresses_service_name_json
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --nn --format json)
set_tests_properties(policy_resolver_nn_suppresses_service_name_json PROPERTIES
  FAIL_REGULAR_EXPRESSION "_port_service")

# --nn only disables service names -- OUI vendor annotation (an independent, still-default-on
# lookup) must still appear.
add_test(NAME policy_resolver_nn_does_not_affect_oui
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --nn)
set_tests_properties(policy_resolver_nn_does_not_affect_oui PROPERTIES
  PASS_REGULAR_EXPRESSION "mac: 00:0c:29:11:22:33 \\(VMware\\)")

add_test(NAME policy_resolver_services_file_overrides_builtin_table_text
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --services "${RESOLVER_SERVICES}")
set_tests_properties(policy_resolver_services_file_overrides_builtin_table_text PROPERTIES
  # 502/tcp: overridden from the built-in "modbus" to "custom-modbus" -- FlowReport's server_port
  # is the only port it carries (no client port -- see FlowReport's own comment), so unlike
  # decode's own equivalent test, there's no client-side port to also exercise the "supplement" half.
  PASS_REGULAR_EXPRESSION "192.168.1.10:502 \\(custom-modbus\\)"
  FAIL_REGULAR_EXPRESSION "\\(modbus\\)")

add_test(NAME policy_resolver_all_enabled_together_text
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --resolve --hosts "${RESOLVER_HOSTS}" --services "${RESOLVER_SERVICES}")
set_tests_properties(policy_resolver_all_enabled_together_text PROPERTIES
  PASS_REGULAR_EXPRESSION "192.168.1.50 \\(hmi-01\\) -> 192.168.1.10 \\(plc-01\\):502 \\(custom-modbus\\).*mac: 00:0c:29:11:22:33 \\(VMware\\) -> 00:0c:29:aa:bb:cc \\(VMware\\)")

add_test(NAME policy_resolver_all_enabled_together_json
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --resolve --hosts "${RESOLVER_HOSTS}" --services "${RESOLVER_SERVICES}" --format json)
set_tests_properties(policy_resolver_all_enabled_together_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"client_mac_vendor\": \"VMware\",[^}]*\"server_mac_vendor\": \"VMware\",[^}]*\"client_hostname\": \"hmi-01\",[^}]*\"server_hostname\": \"plc-01\",[^}]*\"server_port_service\": \"custom-modbus\",")

# --- Bad --hosts/--services paths rejected cleanly at CLI-parse time, same as decode's own -----

add_test(NAME policy_resolver_bad_hosts_path_rejected
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --resolve --hosts "${CMAKE_CURRENT_SOURCE_DIR}/tests/does_not_exist_hosts.txt")
set_tests_properties(policy_resolver_bad_hosts_path_rejected PROPERTIES
  WILL_FAIL TRUE)

add_test(NAME policy_resolver_bad_services_path_rejected
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${POLICY_DIR}/compliant.yaml" --services "${CMAKE_CURRENT_SOURCE_DIR}/tests/does_not_exist_services.txt")
set_tests_properties(policy_resolver_bad_services_path_rejected PROPERTIES
  WILL_FAIL TRUE)

# --- EthernetFlowReport (VLAN-zone L2 flows): OUI vendor annotation only -- no IP/port exists ---

add_test(NAME policy_resolver_ethernet_flow_oui_vendor_shown_by_default_text
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vlan_zones.pcap" --policy "${POLICY_DIR}/vlan_zone_mixed_results.yaml")
set_tests_properties(policy_resolver_ethernet_flow_oui_vendor_shown_by_default_text PROPERTIES
  PASS_REGULAR_EXPRESSION "00:0c:29:11:22:33 \\(VMware\\) <-> 00:0c:29:aa:bb:cc \\(VMware\\)  \\(profinet")

add_test(NAME policy_resolver_ethernet_flow_no_oui_suppresses_vendor_text
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vlan_zones.pcap" --policy "${POLICY_DIR}/vlan_zone_mixed_results.yaml" --no-oui)
set_tests_properties(policy_resolver_ethernet_flow_no_oui_suppresses_vendor_text PROPERTIES
  PASS_REGULAR_EXPRESSION "00:0c:29:11:22:33 <-> 00:0c:29:aa:bb:cc  \\(profinet"
  FAIL_REGULAR_EXPRESSION "VMware")

add_test(NAME policy_resolver_ethernet_flow_oui_vendor_json
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vlan_zones.pcap" --policy "${POLICY_DIR}/vlan_zone_mixed_results.yaml" --format json)
set_tests_properties(policy_resolver_ethernet_flow_oui_vendor_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mac_a\": \"00:0c:29:11:22:33\",\n *\"mac_b\": \"00:0c:29:aa:bb:cc\",\n *\"mac_a_vendor\": \"VMware\",\n *\"mac_b_vendor\": \"VMware\",")

add_test(NAME policy_resolver_ethernet_flow_no_oui_suppresses_vendor_json
  COMMAND conduitscope policy validate --read "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_vlan_zones.pcap" --policy "${POLICY_DIR}/vlan_zone_mixed_results.yaml" --no-oui --format json)
set_tests_properties(policy_resolver_ethernet_flow_no_oui_suppresses_vendor_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mac_a\": \"00:0c:29:11:22:33\","
  FAIL_REGULAR_EXPRESSION "mac_._vendor")

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
