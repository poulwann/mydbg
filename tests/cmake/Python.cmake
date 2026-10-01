add_executable(python_cross_arch_tests
  ${PROJECT_SOURCE_DIR}/tests/python_cross_arch.cpp
)
target_link_libraries(python_cross_arch_tests PRIVATE scripting_engine)
mydbg_enable_warnings(python_cross_arch_tests)
mydbg_configure_analysis_runtime(python_cross_arch_tests)
set_target_properties(python_cross_arch_tests PROPERTIES ENABLE_EXPORTS ON)

add_dependencies(python_cross_arch_tests debuggee_crackme_x86_64)
set(MYDBG_CROSS_ARCH_SCRIPT
  "${PROJECT_SOURCE_DIR}/tests/scripts/cross_arch_debugger.py"
)
mydbg_add_test(
  NAME python_cross_x86_64
  COMMAND python_cross_arch_tests "${MYDBG_CROSS_ARCH_SCRIPT}"
    --native x86_64 $<TARGET_FILE:debuggee_crackme_x86_64> CTF!
)
set_tests_properties(python_cross_x86_64 PROPERTIES TIMEOUT 120)

add_executable(lldb_engine_scripting_tests
  ${PROJECT_SOURCE_DIR}/tests/lldb_engine_scripting.cpp
)
target_link_libraries(lldb_engine_scripting_tests PRIVATE debugger_engine)
mydbg_enable_warnings(lldb_engine_scripting_tests)
mydbg_configure_analysis_runtime(lldb_engine_scripting_tests)
mydbg_add_test(
  NAME lldb_engine_scripting
  COMMAND lldb_engine_scripting_tests
    $<TARGET_FILE:debuggee_interactive>
    $<TARGET_FILE:debuggee_attach>
    $<TARGET_FILE_DIR:debuggee_interactive>
)
set_tests_properties(lldb_engine_scripting PROPERTIES TIMEOUT 45)
add_executable(python_runtime_tests
  ${PROJECT_SOURCE_DIR}/tests/python_runtime.cpp
)
target_link_libraries(python_runtime_tests PRIVATE scripting_engine)
mydbg_enable_warnings(python_runtime_tests)
mydbg_configure_analysis_runtime(python_runtime_tests)
set_target_properties(python_runtime_tests PROPERTIES ENABLE_EXPORTS ON)
mydbg_add_test(
  NAME python_runtime
  COMMAND python_runtime_tests
    "${PROJECT_SOURCE_DIR}/tests/scripts/integration.py"
    "${PROJECT_SOURCE_DIR}/tests/scripts/runtime_behaviors.py"
    "${PROJECT_SOURCE_DIR}/tests/scripts/failure.py"
    "${PROJECT_SOURCE_DIR}/tests/scripts/blocking.py"
    "${PROJECT_SOURCE_DIR}/tests/scripts/debuggable.py"
)
set_tests_properties(python_runtime PROPERTIES
  TIMEOUT 75
  ENVIRONMENT
    "MYDBG_TEST_INTERACTIVE=$<TARGET_FILE:debuggee_interactive>;MYDBG_TEST_WORKING_DIRECTORY=$<TARGET_FILE_DIR:debuggee_interactive>;MYDBG_TEST_ATTACH=$<TARGET_FILE:debuggee_attach>;MYDBG_TEST_BASIC=$<TARGET_FILE:debuggee_basic>"
)
mydbg_add_test(
  NAME ctf_script_demo
  COMMAND mydbg --headless-script
    "${PROJECT_SOURCE_DIR}/examples/solve_ctf.py"
)
set_tests_properties(ctf_script_demo PROPERTIES
  TIMEOUT 30
  ENVIRONMENT
    "MYDBG_CTF_CHALLENGE=$<TARGET_FILE:ctf_challenge>"
  PASS_REGULAR_EXPRESSION
    "flag\\{scripted_debuggers_turn_runtime_state_into_answers\\}"
)
