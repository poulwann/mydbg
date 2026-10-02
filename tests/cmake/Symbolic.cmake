mydbg_add_test(
  NAME rop_stack_trace
  COMMAND "${Python_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/tests/symbolic_solver.py"
    --mydbg $<TARGET_FILE:mydbg>
    --script "${PROJECT_SOURCE_DIR}/tests/scripts/rop_trace.py"
    --target "$<TARGET_FILE:debuggee_rop_trace>"
    --timeout-seconds 90
    --expect "rop-trace-ok"
)
set_tests_properties(rop_stack_trace PROPERTIES
  TIMEOUT 120
  SKIP_RETURN_CODE 77
  PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
)

mydbg_add_test(
  NAME symbolic_script_x86_64
  COMMAND "${Python_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/tests/symbolic_solver.py"
    --mydbg $<TARGET_FILE:mydbg>
    --script "${PROJECT_SOURCE_DIR}/examples/solve_symbolic.py"
    --target "$<TARGET_FILE:debuggee_crackme_x86_64>"
    --timeout-seconds 240
    --expect "crackme solved symbolically"
)
set_tests_properties(symbolic_script_x86_64 PROPERTIES
  TIMEOUT 420
  SKIP_RETURN_CODE 77
  PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
)
mydbg_add_test(
  NAME rop_script_x86_64
  COMMAND "${Python_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/tests/symbolic_solver.py"
    --mydbg $<TARGET_FILE:mydbg>
    --script "${PROJECT_SOURCE_DIR}/examples/rop_crackme.py"
    --target "$<TARGET_FILE:debuggee_rop_target>"
    --timeout-seconds 240
    --expect "rop-loop-ok"
)
set_tests_properties(rop_script_x86_64 PROPERTIES
  TIMEOUT 420
  SKIP_RETURN_CODE 77
  PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
)
mydbg_add_test(
  NAME symbolic_script_stdin
  COMMAND "${Python_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/tests/symbolic_solver.py"
    --mydbg $<TARGET_FILE:mydbg>
    --script "${PROJECT_SOURCE_DIR}/examples/solve_stdin.py"
    --target "$<TARGET_FILE:debuggee_symbolic_stdin>"
    --timeout-seconds 420
    --expect "stdin-solve-ok"
)
set_tests_properties(symbolic_script_stdin PROPERTIES
  TIMEOUT 600
  SKIP_RETURN_CODE 77
  PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
)
mydbg_add_test(
  NAME symbolic_script_trace
  COMMAND "${Python_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/tests/symbolic_solver.py"
    --mydbg $<TARGET_FILE:mydbg>
    --script "${PROJECT_SOURCE_DIR}/examples/solve_trace.py"
    --target "$<TARGET_FILE:debuggee_crackme_x86_64>"
    --timeout-seconds 240
    --expect "trace-solve-ok"
)
set_tests_properties(symbolic_script_trace PROPERTIES
  TIMEOUT 420
  SKIP_RETURN_CODE 77
  PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
)
foreach(emporium_test IN ITEMS ret2win_x64 ret2win_i386 ret2win_arm split_x64 callme_x64 write4_x64)
  string(REPLACE "_" "-" emporium_marker "${emporium_test}")
  mydbg_add_test(
    NAME rop_emporium_${emporium_test}
    COMMAND "${Python_EXECUTABLE}"
      "${PROJECT_SOURCE_DIR}/tests/symbolic_solver.py"
      --mydbg $<TARGET_FILE:mydbg>
      --script "${PROJECT_SOURCE_DIR}/examples/rop_emporium/solve_${emporium_test}.py"
      --target "$<TARGET_FILE:debuggee_crackme_x86_64>"
      --timeout-seconds 300
      --expect "${emporium_marker}-solve-ok"
  )
  set_tests_properties(rop_emporium_${emporium_test} PROPERTIES
    TIMEOUT 420
    SKIP_RETURN_CODE 77
    PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
  )
endforeach()
mydbg_add_test(
  NAME symbolic_script_keygen
  COMMAND "${Python_EXECUTABLE}"
    "${PROJECT_SOURCE_DIR}/tests/symbolic_solver.py"
    --mydbg $<TARGET_FILE:mydbg>
    --script "${PROJECT_SOURCE_DIR}/examples/solve_keygen.py"
    --target "$<TARGET_FILE:debuggee_keygenme>"
    --timeout-seconds 420
    --expect "keygen-solve-ok"
)
set_tests_properties(symbolic_script_keygen PROPERTIES
  TIMEOUT 600
  SKIP_RETURN_CODE 77
  PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
)

if(MYDBG_CROSS_ARCH_TESTS)
  foreach(architecture IN ITEMS mips32 ppc32)
    string(TOUPPER "${architecture}" architecture_upper)
    if(architecture STREQUAL "mips32")
      set(qemu "${QEMU_MIPSEL_EXECUTABLE}")
      set(qemu_machine "mipsel")
      set(pointer_options)
    else()
      set(qemu "${QEMU_PPC_EXECUTABLE}")
      set(qemu_machine "ppc")
      # LLDB's function breakpoint lands after crackme_entry's prologue, which
      # has already moved the input pointer to the saved frame slot.
      set(pointer_options --ptr-slot "r31:24")
    endif()
    mydbg_add_test(
      NAME symbolic_script_${architecture}
      COMMAND "${Python_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/symbolic_solver.py"
        --mydbg $<TARGET_FILE:mydbg>
        --script "${PROJECT_SOURCE_DIR}/tests/scripts/symbolic_solve.py"
        --target "${MYDBG_${architecture_upper}_FIXTURE}"
        --qemu "${qemu}"
        --ptr-regs "a0,r4,r3"
        ${pointer_options}
    )
    set_tests_properties(symbolic_script_${architecture} PROPERTIES
      TIMEOUT 600
      SKIP_RETURN_CODE 77
      PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
      RESOURCE_LOCK qemu_${architecture}
    )
  endforeach()
endif()
