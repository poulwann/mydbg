find_program(MYDBG_CROSS_CLANG_EXECUTABLE NAMES clang-22 clang REQUIRED)
find_program(MYDBG_LLD_EXECUTABLE NAMES ld.lld lld REQUIRED)
find_program(QEMU_ARM_EXECUTABLE NAMES qemu-arm REQUIRED)
find_program(QEMU_MIPSEL_EXECUTABLE NAMES qemu-mipsel REQUIRED)
find_program(QEMU_PPC_EXECUTABLE NAMES qemu-ppc REQUIRED)

set(MYDBG_CROSS_FIXTURE_DIR
  "${PROJECT_BINARY_DIR}/cross-architecture-fixtures"
)
set(MYDBG_ARM32_FIXTURE
  "${MYDBG_CROSS_FIXTURE_DIR}/debuggee_crackme_arm32"
)
set(MYDBG_MIPS32_FIXTURE
  "${MYDBG_CROSS_FIXTURE_DIR}/debuggee_crackme_mips32"
)
set(MYDBG_PPC32_FIXTURE
  "${MYDBG_CROSS_FIXTURE_DIR}/debuggee_crackme_ppc32"
)

function(mydbg_add_cross_fixture architecture triple)
  string(TOUPPER "${architecture}" architecture_upper)
  set(fixture "${MYDBG_${architecture_upper}_FIXTURE}")
  add_custom_command(
    OUTPUT "${fixture}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${MYDBG_CROSS_FIXTURE_DIR}"
    COMMAND "${MYDBG_CROSS_CLANG_EXECUTABLE}"
      "--target=${triple}"
      "-fuse-ld=${MYDBG_LLD_EXECUTABLE}"
      -std=c11 -g -O0 -ffreestanding -fno-omit-frame-pointer
      -fno-optimize-sibling-calls -fno-stack-protector ${ARGN}
      "${PROJECT_SOURCE_DIR}/tests/debuggees/crackme_${architecture}.c"
      -o "${fixture}"
    DEPENDS ${PROJECT_SOURCE_DIR}/tests/debuggees/crackme_${architecture}.c
    VERBATIM
  )
  add_custom_target(debuggee_crackme_${architecture} ALL DEPENDS "${fixture}")
endfunction()
mydbg_add_cross_fixture(arm32 armv7a-linux-gnueabi
  -fno-pic -fno-pie -marm -march=armv7-a -mfloat-abi=soft -nostdlib -static
  -Wl,-e,_start,--build-id=none,-z,noexecstack)
mydbg_add_cross_fixture(mips32 mipsel-linux-gnu
  -fno-builtin -fno-pic -fno-pie -mno-abicalls -G0 -mabi=32 -march=mips32r2
  -nostdlib -static -Wl,-e,_start,--build-id=none,-z,noexecstack)
mydbg_add_cross_fixture(ppc32 powerpc-linux-gnu
  -fno-pic -fno-pie -m32 -mbig-endian -mcpu=powerpc -nostdlib -static
  -Wl,-e,_start,--build-id=none,--no-gc-sections,-z,noexecstack)
