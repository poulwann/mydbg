option(MYDBG_CROSS_ARCH_TESTS "Build and run cross-architecture QEMU scenarios" ON)
option(MYDBG_SYMBOLIC_TESTS "Register optional symbolic execution and ROP scenarios" ON)

include(cmake/Fixtures.cmake)
if(MYDBG_CROSS_ARCH_TESTS)
  include(cmake/CrossFixtures.cmake)
endif()

add_executable(mydbg_scenarios
  scenarios/main.cpp
  scenarios/DebuggerScenarios.cpp
  scenarios/UiSettings.cpp)
target_link_libraries(mydbg_scenarios PRIVATE app_ui)
set_target_properties(mydbg_scenarios PROPERTIES ENABLE_EXPORTS ON)
mydbg_enable_warnings(mydbg_scenarios)
mydbg_configure_analysis_runtime(mydbg_scenarios)

# Resolve executable targets before wrapping the command; add_test only expands
# a target name when it is the command's first argument.
function(mydbg_add_test)
  cmake_parse_arguments(PARSE_ARGV 0 test "" "NAME" "COMMAND")
  list(POP_FRONT test_COMMAND executable)
  if(TARGET "${executable}")
    set(executable "$<TARGET_FILE:${executable}>")
  endif()
  add_test(NAME "${test_NAME}"
    COMMAND "${Python_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/isolated_session.py"
      "${executable}" ${test_COMMAND})
endfunction()

# Includes share fixture variables; only tests introduced by a suite get its label.
macro(mydbg_test_suite suite label)
  get_property(tests_before DIRECTORY PROPERTY TESTS)
  include("cmake/${suite}.cmake")
  get_property(suite_tests DIRECTORY PROPERTY TESTS)
  if(tests_before)
    list(REMOVE_ITEM suite_tests ${tests_before})
  endif()
  if(suite_tests)
    set_tests_properties(${suite_tests} PROPERTIES LABELS "${label}")
  endif()
endmacro()

mydbg_test_suite(Unit unit)
mydbg_test_suite(Native native)
mydbg_test_suite(Dwarf dwarf)
mydbg_test_suite(Python python)
if(MYDBG_CROSS_ARCH_TESTS)
  mydbg_test_suite(Cross cross)
endif()
if(MYDBG_SYMBOLIC_TESTS)
  mydbg_test_suite(Symbolic symbolic)
endif()

get_property(all_tests DIRECTORY PROPERTY TESTS)
set_tests_properties(${all_tests} PROPERTIES WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
