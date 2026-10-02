find_program(LLDB_SERVER_EXECUTABLE NAMES lldb-server-18.1.3 lldb-server REQUIRED)

add_library(test_debugger_plugin MODULE
  ${PROJECT_SOURCE_DIR}/tests/plugins/test_plugin.cpp
)
target_include_directories(test_debugger_plugin PRIVATE ${PROJECT_SOURCE_DIR}/src)
set_target_properties(test_debugger_plugin PROPERTIES
  PREFIX ""
  LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/test-plugins"
)
mydbg_enable_warnings(test_debugger_plugin)
mydbg_add_test(
  NAME headless_keybindings
  COMMAND mydbg_scenarios --headless-keybindings
)
mydbg_add_test(
  NAME headless_vertical_slice
  COMMAND mydbg_scenarios --headless $<TARGET_FILE:debuggee_basic>
    $<TARGET_FILE:debuggee_attach>
)
set_tests_properties(headless_vertical_slice PROPERTIES
  ENVIRONMENT
    "MYDBG_PLUGIN_PATH=$<TARGET_FILE_DIR:test_debugger_plugin>;MYDBG_REQUIRE_TEST_PLUGIN=1"
)
set_tests_properties(headless_vertical_slice PROPERTIES TIMEOUT 60)
mydbg_add_test(
  NAME headless_scripted_condition
  COMMAND mydbg_scenarios --headless-condition
    $<TARGET_FILE:debuggee_condition>
)
set_tests_properties(headless_scripted_condition PROPERTIES TIMEOUT 90)
mydbg_add_test(
  NAME headless_glibc_heap
  COMMAND mydbg_scenarios --headless-heap $<TARGET_FILE:debuggee_heap>
)
set_tests_properties(headless_glibc_heap PROPERTIES TIMEOUT 90)
mydbg_add_test(
  NAME headless_scans
  COMMAND mydbg_scenarios --headless-scans $<TARGET_FILE:debuggee_scans>
)
set_tests_properties(headless_scans PROPERTIES TIMEOUT 90)
mydbg_add_test(
  NAME headless_stop_intelligence
  COMMAND mydbg_scenarios --headless-intelligence
    $<TARGET_FILE:debuggee_intelligence>
)
set_tests_properties(headless_stop_intelligence PROPERTIES TIMEOUT 30)
add_executable(python_lldb_coexistence_tests
  ${PROJECT_SOURCE_DIR}/tests/python_lldb_coexistence.cpp
)
target_link_libraries(python_lldb_coexistence_tests
  PRIVATE scripting_engine pybind11::embed
)
mydbg_enable_warnings(python_lldb_coexistence_tests)
mydbg_configure_analysis_runtime(python_lldb_coexistence_tests)
mydbg_add_test(
  NAME python_lldb_coexistence
  COMMAND python_lldb_coexistence_tests
)
set_tests_properties(python_lldb_coexistence PROPERTIES TIMEOUT 30)
add_executable(lldb_engine_command_tests
  ${PROJECT_SOURCE_DIR}/tests/lldb_engine_commands.cpp
)
target_link_libraries(lldb_engine_command_tests PRIVATE debugger_engine)
mydbg_enable_warnings(lldb_engine_command_tests)
mydbg_configure_analysis_runtime(lldb_engine_command_tests)
mydbg_add_test(
  NAME lldb_engine_commands
  COMMAND lldb_engine_command_tests $<TARGET_FILE:debuggee_basic>
)
set_tests_properties(lldb_engine_commands PROPERTIES
  TIMEOUT 30
  ENVIRONMENT "MYDBG_TRANSLATION=${PROJECT_SOURCE_DIR}/tests/locales/command_status.ini"
)
add_library(remote_process_harness STATIC
  ${PROJECT_SOURCE_DIR}/tests/RemoteProcessHarness.cpp
)
target_link_libraries(remote_process_harness PUBLIC debugger_engine)
mydbg_enable_warnings(remote_process_harness)

add_executable(lldb_engine_remote_tests
  ${PROJECT_SOURCE_DIR}/tests/lldb_engine_remote.cpp
)
target_link_libraries(lldb_engine_remote_tests
  PRIVATE remote_process_harness
)
mydbg_enable_warnings(lldb_engine_remote_tests)
mydbg_configure_analysis_runtime(lldb_engine_remote_tests)
mydbg_add_test(
  NAME lldb_engine_remote
  COMMAND lldb_engine_remote_tests $<TARGET_FILE:debuggee_basic>
    "${LLDB_SERVER_EXECUTABLE}"
)
set_tests_properties(lldb_engine_remote PROPERTIES TIMEOUT 60)
add_executable(lldb_engine_remote_lifecycle_tests
  ${PROJECT_SOURCE_DIR}/tests/lldb_engine_remote_lifecycle.cpp
)
target_link_libraries(lldb_engine_remote_lifecycle_tests
  PRIVATE debugger_engine
)
mydbg_enable_warnings(lldb_engine_remote_lifecycle_tests)
mydbg_configure_analysis_runtime(lldb_engine_remote_lifecycle_tests)
mydbg_add_test(
  NAME lldb_engine_remote_lifecycle
  COMMAND lldb_engine_remote_lifecycle_tests
    $<TARGET_FILE:debuggee_basic> "${LLDB_SERVER_EXECUTABLE}"
)
set_tests_properties(lldb_engine_remote_lifecycle PROPERTIES TIMEOUT 60)

function(mydbg_configure_architecture_test target)
  target_link_libraries(${target} PRIVATE debugger_engine decompiler_engine)
  mydbg_enable_warnings(${target})
  mydbg_configure_analysis_runtime(${target})
endfunction()


add_executable(lldb_engine_x86_64_tests
  ${PROJECT_SOURCE_DIR}/tests/lldb_engine_x86_64.cpp
)
mydbg_configure_architecture_test(lldb_engine_x86_64_tests)
add_dependencies(lldb_engine_x86_64_tests debuggee_crackme_x86_64)
mydbg_add_test(
  NAME robustness_x86_64
  COMMAND lldb_engine_x86_64_tests
    $<TARGET_FILE:debuggee_crackme_x86_64>
)
set_tests_properties(robustness_x86_64 PROPERTIES TIMEOUT 90)
