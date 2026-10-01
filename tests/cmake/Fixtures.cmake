foreach(fixture IN ITEMS basic condition attach interactive heap scans intelligence)
  add_executable(debuggee_${fixture} ${PROJECT_SOURCE_DIR}/tests/debuggees/${fixture}.cpp)
  target_compile_options(debuggee_${fixture} PRIVATE
    -g -O0 -fno-omit-frame-pointer)
  if(NOT fixture STREQUAL "basic")
    mydbg_enable_warnings(debuggee_${fixture})
  endif()
endforeach()
# The native command scenario inspects .got.plt; eager binding can merge it
# into .got on hardened toolchains. Keep this fixture's ELF layout explicit.
target_link_options(debuggee_basic PRIVATE -Wl,-z,lazy)

add_executable(debuggee_crackme_x86_64
  ${PROJECT_SOURCE_DIR}/tests/debuggees/crackme_x86_64.c
)
target_compile_options(debuggee_crackme_x86_64 PRIVATE
  -g -O0 -fno-omit-frame-pointer -fno-optimize-sibling-calls
  $<$<C_COMPILER_ID:Clang,GNU>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
)
add_executable(debuggee_rop_target ${PROJECT_SOURCE_DIR}/tests/debuggees/rop_target.c)
target_compile_options(debuggee_rop_target PRIVATE
  -g -O0 -fno-stack-protector -fno-omit-frame-pointer -no-pie
)
target_link_options(debuggee_rop_target PRIVATE -no-pie)
add_executable(debuggee_symbolic_stdin ${PROJECT_SOURCE_DIR}/tests/debuggees/symbolic_stdin.c)
target_compile_options(debuggee_symbolic_stdin PRIVATE
  -g -O0 -fno-stack-protector -fno-omit-frame-pointer
)
add_executable(debuggee_keygenme ${PROJECT_SOURCE_DIR}/tests/debuggees/keygenme.c)
target_compile_options(debuggee_keygenme PRIVATE
  -g -O0 -fno-stack-protector -fno-omit-frame-pointer -no-pie
)
target_link_options(debuggee_keygenme PRIVATE -no-pie)
