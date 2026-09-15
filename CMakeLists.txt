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

add_test(NAME stats_mode_dnp3
  COMMAND conduitscope decode --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_dnp3.pcap" --stats)
set_tests_properties(stats_mode_dnp3 PROPERTIES
  PASS_REGULAR_EXPRESSION "dnp3 function codes:")

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

add_test(NAME policy_validate_is_a_documented_stub
  COMMAND conduitscope policy validate --input "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap" --policy "${CMAKE_CURRENT_SOURCE_DIR}/tests/sample_modbus.pcap")
set_tests_properties(policy_validate_is_a_documented_stub PROPERTIES
  PASS_REGULAR_EXPRESSION "not implemented")
