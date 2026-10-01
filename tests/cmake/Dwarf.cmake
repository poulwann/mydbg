add_library(debuggee_dwarf_library SHARED ${PROJECT_SOURCE_DIR}/tests/debuggees/dwarf_library.cpp)
target_compile_options(debuggee_dwarf_library PRIVATE
  -gdwarf-5 -O0 -fno-omit-frame-pointer)
add_executable(dwarf_var_storage_tests ${PROJECT_SOURCE_DIR}/tests/dwarf_var_storage.c)
target_link_libraries(dwarf_var_storage_tests PRIVATE
  PkgConfig::RIZIN ${BZIP2_LIBRARIES})
set_target_properties(dwarf_var_storage_tests PROPERTIES
  BUILD_RPATH "${RIZIN_LIBRARY_DIRS}")
target_link_options(dwarf_var_storage_tests PRIVATE
  $<$<PLATFORM_ID:Linux>:-Wl,--disable-new-dtags>)
mydbg_add_test(NAME dwarf_var_storage COMMAND dwarf_var_storage_tests)
set_source_files_properties(${PROJECT_SOURCE_DIR}/tests/debuggees/dwarf_secondary.cpp
  PROPERTIES COMPILE_OPTIONS "-O2")
foreach(dwarf_version IN ITEMS 4 5)
  foreach(dwarf_layout IN ITEMS embedded split)
    set(dwarf_target "debuggee_dwarf${dwarf_version}_${dwarf_layout}")
    add_executable(${dwarf_target}
      ${PROJECT_SOURCE_DIR}/tests/debuggees/dwarf.cpp ${PROJECT_SOURCE_DIR}/tests/debuggees/dwarf_secondary.cpp)
    target_compile_options(${dwarf_target} PRIVATE
      "-gdwarf-${dwarf_version}" -O0 -fno-omit-frame-pointer -fPIE)
    target_link_options(${dwarf_target} PRIVATE -pie -Wl,--build-id=sha1)
    target_link_libraries(${dwarf_target} PRIVATE debuggee_dwarf_library)
    if(dwarf_layout STREQUAL "split")
      target_compile_options(${dwarf_target} PRIVATE -gsplit-dwarf)
    endif()
  endforeach()
endforeach()

add_executable(debuggee_session_exception ${PROJECT_SOURCE_DIR}/tests/debuggees/session_exception.cpp)
target_compile_options(debuggee_session_exception PRIVATE
  -g -O0 -fno-omit-frame-pointer)
add_executable(session_persistence_tests ${PROJECT_SOURCE_DIR}/tests/session_persistence.cpp)
mydbg_configure_architecture_test(session_persistence_tests)
add_dependencies(session_persistence_tests
  debuggee_dwarf5_embedded debuggee_session_exception)
mydbg_add_test(NAME session_persistence
  COMMAND session_persistence_tests $<TARGET_FILE:debuggee_dwarf5_embedded>
    $<TARGET_FILE:debuggee_session_exception>)
set_tests_properties(session_persistence PROPERTIES TIMEOUT 90)

set(MYDBG_DWARF_DEBUG_FILE "${PROJECT_BINARY_DIR}/dwarf.debug")
set(MYDBG_DWARF_DEBUGLINK_FILE "${PROJECT_BINARY_DIR}/debuggee_dwarf_debuglink")
set(MYDBG_DWARF_STRIPPED_FILE "${PROJECT_BINARY_DIR}/debuggee_dwarf_stripped")
add_custom_command(
  OUTPUT "${MYDBG_DWARF_DEBUG_FILE}" "${MYDBG_DWARF_DEBUGLINK_FILE}"
    "${MYDBG_DWARF_STRIPPED_FILE}"
  COMMAND "${CMAKE_OBJCOPY}" --only-keep-debug
    $<TARGET_FILE:debuggee_dwarf5_embedded> "${MYDBG_DWARF_DEBUG_FILE}"
  COMMAND "${CMAKE_OBJCOPY}" --strip-debug
    "--add-gnu-debuglink=${MYDBG_DWARF_DEBUG_FILE}"
    $<TARGET_FILE:debuggee_dwarf5_embedded> "${MYDBG_DWARF_DEBUGLINK_FILE}"
  COMMAND "${CMAKE_OBJCOPY}" --strip-debug
    $<TARGET_FILE:debuggee_dwarf5_embedded> "${MYDBG_DWARF_STRIPPED_FILE}"
  DEPENDS debuggee_dwarf5_embedded
  VERBATIM)
add_custom_target(debuggee_dwarf_external ALL DEPENDS
  "${MYDBG_DWARF_DEBUG_FILE}" "${MYDBG_DWARF_DEBUGLINK_FILE}"
  "${MYDBG_DWARF_STRIPPED_FILE}")
add_executable(dwarf_debug_info_tests ${PROJECT_SOURCE_DIR}/tests/dwarf_debug_info.cpp)
mydbg_configure_architecture_test(dwarf_debug_info_tests)
add_dependencies(dwarf_debug_info_tests debuggee_dwarf_external
  debuggee_dwarf4_embedded debuggee_dwarf4_split debuggee_dwarf5_split)
foreach(dwarf_version IN ITEMS 4 5)
  foreach(dwarf_layout IN ITEMS embedded split)
    mydbg_add_test(NAME "dwarf${dwarf_version}_${dwarf_layout}"
      COMMAND dwarf_debug_info_tests
        "$<TARGET_FILE:debuggee_dwarf${dwarf_version}_${dwarf_layout}>"
        embedded)
    set_tests_properties("dwarf${dwarf_version}_${dwarf_layout}"
      PROPERTIES TIMEOUT 90)
  endforeach()
endforeach()
mydbg_add_test(NAME dwarf_debuglink COMMAND dwarf_debug_info_tests
  "${MYDBG_DWARF_DEBUGLINK_FILE}" debuglink)
mydbg_add_test(NAME dwarf_explicit COMMAND dwarf_debug_info_tests
  "${MYDBG_DWARF_STRIPPED_FILE}" explicit "${MYDBG_DWARF_DEBUG_FILE}")
mydbg_add_test(NAME dwarf_stripped COMMAND dwarf_debug_info_tests
  "${MYDBG_DWARF_STRIPPED_FILE}" stripped)
set_tests_properties(dwarf_debuglink dwarf_explicit dwarf_stripped
  PROPERTIES TIMEOUT 90)

