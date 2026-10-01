foreach(architecture IN ITEMS arm32 mips32 ppc32)
  string(TOUPPER "${architecture}" architecture_upper)
  if(architecture STREQUAL "arm32")
    set(qemu "${QEMU_ARM_EXECUTABLE}")
    set(robustness_timeout 120)
  elseif(architecture STREQUAL "mips32")
    set(qemu "${QEMU_MIPSEL_EXECUTABLE}")
    set(robustness_timeout 180)
  else()
    set(qemu "${QEMU_PPC_EXECUTABLE}")
    set(robustness_timeout 120)
  endif()
  add_executable(lldb_engine_${architecture}_tests
    ${PROJECT_SOURCE_DIR}/tests/lldb_engine_${architecture}.cpp)
  mydbg_configure_architecture_test(lldb_engine_${architecture}_tests)
  target_link_libraries(lldb_engine_${architecture}_tests
    PRIVATE remote_process_harness)
  add_dependencies(lldb_engine_${architecture}_tests
    debuggee_crackme_${architecture})
  mydbg_add_test(NAME robustness_${architecture}
    COMMAND lldb_engine_${architecture}_tests
      "${MYDBG_${architecture_upper}_FIXTURE}" "${qemu}")
  set_tests_properties(robustness_${architecture} PROPERTIES
    TIMEOUT ${robustness_timeout})
endforeach()

add_dependencies(python_cross_arch_tests
  debuggee_crackme_arm32 debuggee_crackme_mips32 debuggee_crackme_ppc32)
foreach(architecture IN ITEMS arm32 mips32 ppc32)
  string(TOUPPER "${architecture}" architecture_upper)
  string(REGEX REPLACE "32$" "" machine "${architecture}")
  if(architecture STREQUAL "mips32")
    set(qemu "${QEMU_MIPSEL_EXECUTABLE}")
  else()
    string(TOUPPER "${machine}" machine_upper)
    set(qemu "${QEMU_${machine_upper}_EXECUTABLE}")
  endif()
  mydbg_add_test(NAME python_cross_${architecture}
    COMMAND python_cross_arch_tests "${MYDBG_CROSS_ARCH_SCRIPT}"
      --qemu "${machine}" "${MYDBG_${architecture_upper}_FIXTURE}" "${qemu}")
  set_tests_properties(robustness_${architecture} python_cross_${architecture}
    PROPERTIES RESOURCE_LOCK qemu_${architecture})
endforeach()
set_tests_properties(
  python_cross_x86_64 python_cross_arm32 python_cross_mips32 python_cross_ppc32
  PROPERTIES TIMEOUT 120)
add_executable(headless_remote_smoke_tests
  ${PROJECT_SOURCE_DIR}/tests/headless_remote_smoke.cpp
)
target_link_libraries(headless_remote_smoke_tests
  PRIVATE remote_process_harness
)
mydbg_enable_warnings(headless_remote_smoke_tests)
add_dependencies(headless_remote_smoke_tests
  mydbg
  debuggee_crackme_arm32
  debuggee_crackme_mips32
  debuggee_crackme_ppc32
)
foreach(architecture IN ITEMS arm32 mips32 ppc32)
  string(TOUPPER "${architecture}" architecture_upper)
  string(REGEX REPLACE "32$" "" machine "${architecture}")
  if(architecture STREQUAL "mips32")
    set(qemu "${QEMU_MIPSEL_EXECUTABLE}")
  else()
    string(TOUPPER "${machine}" machine_upper)
    set(qemu "${QEMU_${machine_upper}_EXECUTABLE}")
  endif()
  mydbg_add_test(NAME actual_mydbg_${architecture}
    COMMAND headless_remote_smoke_tests $<TARGET_FILE:mydbg>
      "${MYDBG_CROSS_ARCH_SCRIPT}" "${machine}"
      "${MYDBG_${architecture_upper}_FIXTURE}" "${qemu}")
  set_tests_properties(actual_mydbg_${architecture} PROPERTIES
    TIMEOUT 150 RESOURCE_LOCK qemu_${architecture})
endforeach()
