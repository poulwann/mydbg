cmake_minimum_required(VERSION 3.28)

project(mydbg VERSION 0.5 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

if(DEFINED ENV{MYDBG_DEPS_PREFIX})
  set(MYDBG_DEFAULT_DEPS_PREFIX "$ENV{MYDBG_DEPS_PREFIX}")
else()
  set(MYDBG_DEFAULT_DEPS_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/.deps")
endif()
set(MYDBG_DEPS_PREFIX "${MYDBG_DEFAULT_DEPS_PREFIX}" CACHE PATH
  "Optional local prefix populated by scripts/bootstrap-analysis-deps.sh")
if(IS_DIRECTORY "${MYDBG_DEPS_PREFIX}")
  list(PREPEND CMAKE_PREFIX_PATH "${MYDBG_DEPS_PREFIX}")
endif()

find_package(OpenGL REQUIRED)
find_package(BZip2 REQUIRED)
find_package(PNG 1.6 REQUIRED)
find_package(SDL3 CONFIG REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
find_program(LLDB_EXECUTABLE NAMES lldb REQUIRED)
execute_process(
  COMMAND "${LLDB_EXECUTABLE}" --print-script-interpreter-info
  RESULT_VARIABLE LLDB_PYTHON_INFO_RESULT
  OUTPUT_VARIABLE LLDB_PYTHON_INFO
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT LLDB_PYTHON_INFO_RESULT EQUAL 0)
  message(FATAL_ERROR "Unable to query LLDB's Python interpreter")
endif()
string(JSON LLDB_PYTHON_EXECUTABLE ERROR_VARIABLE LLDB_PYTHON_JSON_ERROR
  GET "${LLDB_PYTHON_INFO}" executable)
if(LLDB_PYTHON_JSON_ERROR)
  message(FATAL_ERROR
    "LLDB returned invalid script interpreter information: ${LLDB_PYTHON_INFO}")
endif()
if(NOT Python_EXECUTABLE)
  set(Python_EXECUTABLE "${LLDB_PYTHON_EXECUTABLE}" CACHE FILEPATH
    "Python interpreter used by LLDB")
endif()
find_package(Python 3.12 REQUIRED COMPONENTS Interpreter Development.Embed)
file(REAL_PATH "${Python_EXECUTABLE}" MYDBG_PYTHON_EXECUTABLE)
file(REAL_PATH "${LLDB_PYTHON_EXECUTABLE}" MYDBG_LLDB_PYTHON_EXECUTABLE)
if(NOT MYDBG_PYTHON_EXECUTABLE STREQUAL
   MYDBG_LLDB_PYTHON_EXECUTABLE)
  message(FATAL_ERROR
    "Python/LLDB ABI mismatch: embedding ${MYDBG_PYTHON_EXECUTABLE}, "
    "but LLDB uses ${MYDBG_LLDB_PYTHON_EXECUTABLE}")
endif()
pkg_check_modules(RIZIN REQUIRED IMPORTED_TARGET rz_core=0.8.2)
pkg_get_variable(RIZIN_PLUGIN_SUBDIR rz_core plugindir)
if(RIZIN_PLUGIN_SUBDIR)
  if(IS_ABSOLUTE "${RIZIN_PLUGIN_SUBDIR}")
    set(RIZIN_PLUGIN_DIR_HINT "${RIZIN_PLUGIN_SUBDIR}")
  else()
    set(RIZIN_PLUGIN_DIR_HINT "${RIZIN_PREFIX}/${RIZIN_PLUGIN_SUBDIR}")
  endif()
endif()
find_path(RZ_GHIDRA_INCLUDE_DIR rz_ghidra.h REQUIRED)
find_file(
 RZ_GHIDRA_LIBRARY
 HINTS "${RIZIN_PLUGIN_DIR_HINT}"
 NAMES core_ghidra.so
 PATH_SUFFIXES lib/rizin/plugins rizin/plugins
 REQUIRED
)
get_filename_component(RZ_GHIDRA_PLUGIN_DIR "${RZ_GHIDRA_LIBRARY}" DIRECTORY)
set(RZ_GHIDRA_SLEIGH_DIR "${RZ_GHIDRA_PLUGIN_DIR}/rz_ghidra_sleigh")
if(NOT IS_DIRECTORY "${RZ_GHIDRA_SLEIGH_DIR}")
 message(FATAL_ERROR "rz-ghidra Sleigh specifications not found at ${RZ_GHIDRA_SLEIGH_DIR}")
endif()
find_path(LLDB_INCLUDE_DIR lldb/API/LLDB.h REQUIRED)
find_library(LLDB_LIBRARY NAMES lldb REQUIRED)
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG v3.0.1
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(pybind11)

FetchContent_Declare(
  imgui
  GIT_REPOSITORY https://github.com/ocornut/imgui.git
  GIT_TAG v1.92.9b-docking
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(imgui)

FetchContent_Declare(
  imgui_color_text_edit
  GIT_REPOSITORY https://github.com/BalazsJako/ImGuiColorTextEdit.git
  GIT_TAG ca2f9f1462e3b60e56351bc466acda448c5ea50d
  GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(imgui_color_text_edit)

# Patch fresh build-local copies, leaving the pinned FetchContent checkout intact.
find_package(Git REQUIRED)
set(MYDBG_TEXT_EDITOR_DIR
  "${CMAKE_CURRENT_BINARY_DIR}/generated/imgui-text-editor")
set(MYDBG_TEXT_EDITOR_PATCH_DIR
  "${CMAKE_CURRENT_BINARY_DIR}/generated/imgui-text-editor-patch")
set(MYDBG_TEXT_EDITOR_PATCH
  "${CMAKE_CURRENT_SOURCE_DIR}/patches/imgui-text-editor-python.patch")
set_property(DIRECTORY APPEND PROPERTY
  CMAKE_CONFIGURE_DEPENDS "${MYDBG_TEXT_EDITOR_PATCH}")
file(MAKE_DIRECTORY "${MYDBG_TEXT_EDITOR_DIR}" "${MYDBG_TEXT_EDITOR_PATCH_DIR}")
foreach(EDITOR_FILE IN ITEMS TextEditor.h TextEditor.cpp LICENSE)
  configure_file("${imgui_color_text_edit_SOURCE_DIR}/${EDITOR_FILE}"
    "${MYDBG_TEXT_EDITOR_PATCH_DIR}/${EDITOR_FILE}" COPYONLY)
endforeach()
# The pinned header uses CRLF; normalize it so the maintained patch is LF-only.
file(READ "${MYDBG_TEXT_EDITOR_PATCH_DIR}/TextEditor.h" MYDBG_TEXT_EDITOR_HEADER)
string(REPLACE "\r\n" "\n" MYDBG_TEXT_EDITOR_HEADER "${MYDBG_TEXT_EDITOR_HEADER}")
file(WRITE "${MYDBG_TEXT_EDITOR_PATCH_DIR}/TextEditor.h" "${MYDBG_TEXT_EDITOR_HEADER}")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env --unset=GIT_DIR --unset=GIT_WORK_TREE
    "GIT_CEILING_DIRECTORIES=${MYDBG_TEXT_EDITOR_PATCH_DIR}"
    "${GIT_EXECUTABLE}" apply --whitespace=nowarn "${MYDBG_TEXT_EDITOR_PATCH}"
  WORKING_DIRECTORY "${MYDBG_TEXT_EDITOR_PATCH_DIR}"
  RESULT_VARIABLE MYDBG_TEXT_EDITOR_PATCH_RESULT
  ERROR_VARIABLE MYDBG_TEXT_EDITOR_PATCH_ERROR
)
if(NOT MYDBG_TEXT_EDITOR_PATCH_RESULT EQUAL 0)
  message(FATAL_ERROR
    "Unable to patch ImGuiColorTextEdit: ${MYDBG_TEXT_EDITOR_PATCH_ERROR}")
endif()
foreach(EDITOR_FILE IN ITEMS TextEditor.h TextEditor.cpp LICENSE)
  file(COPY_FILE "${MYDBG_TEXT_EDITOR_PATCH_DIR}/${EDITOR_FILE}"
    "${MYDBG_TEXT_EDITOR_DIR}/${EDITOR_FILE}" ONLY_IF_DIFFERENT)
endforeach()

FetchContent_Declare(
  imgui_markdown
  GIT_REPOSITORY https://github.com/enkisoftware/imgui_markdown.git
  GIT_TAG 4acbf80584753e15ea54eb271129995862daac8f
  GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(imgui_markdown)

set(MYDBG_MANUAL_FILES
  01-getting-started.md
  02-workspace.md
  03-execution.md
  04-breakpoints.md
  05-memory-and-analysis.md
  06-command-reference.md
  07-troubleshooting.md
  08-python-automation.md
  09-settings.md
  10-plugins.md
  11-symbolic-execution.md
)
set(MYDBG_MANUAL_CHAPTERS "")
foreach(CHAPTER_FILE IN LISTS MYDBG_MANUAL_FILES)
  set(CHAPTER_PATH "${CMAKE_CURRENT_SOURCE_DIR}/docs/manual/${CHAPTER_FILE}")
  set_property(DIRECTORY APPEND PROPERTY
    CMAKE_CONFIGURE_DEPENDS "${CHAPTER_PATH}")
  file(READ "${CHAPTER_PATH}" CHAPTER_MARKDOWN)
  string(APPEND MYDBG_MANUAL_CHAPTERS
    "      {\"${CHAPTER_FILE}\", R\"ELFMAN(${CHAPTER_MARKDOWN})ELFMAN\"},\n")
endforeach()
list(LENGTH MYDBG_MANUAL_FILES MYDBG_MANUAL_CHAPTER_COUNT)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
  src/app/ManualContent.h.in
  "${CMAKE_CURRENT_BINARY_DIR}/generated/ManualContent.h"
  @ONLY
)
set_property(DIRECTORY APPEND PROPERTY
  CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/mydbg_default.ini")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/mydbg_default.ini" MYDBG_DEFAULT_LAYOUT)
configure_file(
  src/app/DefaultLayout.h.in
  "${CMAKE_CURRENT_BINARY_DIR}/generated/DefaultLayout.h"
  @ONLY
)

file(GLOB MYDBG_ENGLISH_CATALOGS CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/locales/en/*.ini")
set(MYDBG_LOCALIZATION_HEADERS
  "${CMAKE_CURRENT_BINARY_DIR}/generated/LocalizationKeys.h"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/LocalizationData.h")
add_custom_command(
  OUTPUT ${MYDBG_LOCALIZATION_HEADERS}
  COMMAND "${Python_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate-localization.py"
    --output-dir "${CMAKE_CURRENT_BINARY_DIR}/generated"
    ${MYDBG_ENGLISH_CATALOGS}
  DEPENDS ${MYDBG_ENGLISH_CATALOGS}
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate-localization.py"
  VERBATIM
)
function(mydbg_enable_warnings target)
  target_compile_options(${target} PRIVATE ${ARGN}
    $<$<CXX_COMPILER_ID:Clang,GNU>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>)
endfunction()

function(mydbg_configure_analysis_runtime target)
  set_target_properties(${target} PROPERTIES
    BUILD_RPATH "${RZ_GHIDRA_PLUGIN_DIR};${RIZIN_LIBRARY_DIRS}")
  target_link_options(${target} PRIVATE
    $<$<PLATFORM_ID:Linux>:-Wl,--disable-new-dtags>)
endfunction()

add_library(localization STATIC
  src/localization/Localization.cpp ${MYDBG_LOCALIZATION_HEADERS})
target_include_directories(localization PUBLIC
  src "${CMAKE_CURRENT_BINARY_DIR}/generated")
mydbg_enable_warnings(localization)

add_library(imgui STATIC
  ${imgui_SOURCE_DIR}/imgui.cpp
  ${imgui_SOURCE_DIR}/imgui_demo.cpp
  ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp
  ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl3.cpp
)
target_include_directories(imgui PUBLIC
  ${imgui_SOURCE_DIR}
  ${imgui_SOURCE_DIR}/backends
)
target_link_libraries(imgui PUBLIC SDL3::SDL3 OpenGL::GL)

add_library(imgui_text_editor STATIC
  "${MYDBG_TEXT_EDITOR_DIR}/TextEditor.cpp"
)
target_include_directories(imgui_text_editor SYSTEM PUBLIC
  "${MYDBG_TEXT_EDITOR_DIR}"
)
target_link_libraries(imgui_text_editor PUBLIC imgui)

add_library(session_store STATIC src/backend/session/SessionStore.cpp)
target_include_directories(session_store PUBLIC src)
target_link_libraries(session_store
  PUBLIC localization
  PRIVATE PkgConfig::RIZIN ${BZIP2_LIBRARIES}
)
mydbg_enable_warnings(session_store)

add_library(debugger_engine STATIC
  src/backend/conditions/BreakpointCondition.cpp
  src/backend/lldb/LldbEngine.cpp
  src/backend/lldb/LldbSessions.cpp
  src/backend/lldb/LldbEngineScanning.cpp
  src/backend/lldb/LldbEngineSnapshots.cpp
  src/backend/lldb/LldbEngineUtilities.cpp
  src/plugins/PluginApi.cpp
)
target_include_directories(debugger_engine
  PUBLIC src ${LLDB_INCLUDE_DIR}
)
target_link_libraries(debugger_engine
  PUBLIC localization session_store ${LLDB_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS}
  PRIVATE PkgConfig::RIZIN ${BZIP2_LIBRARIES}
)
mydbg_enable_warnings(debugger_engine)
add_library(scripting_engine STATIC
  src/scripting/PythonHost.cpp
  src/scripting/PythonRuntime.cpp
  src/scripting/PythonBindings.cpp
)
target_include_directories(scripting_engine PUBLIC src)
target_link_libraries(scripting_engine
  PUBLIC debugger_engine
  PRIVATE pybind11::embed
)
target_compile_definitions(scripting_engine PRIVATE
  MYDBG_PYTHON_PACKAGE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/python"
)
mydbg_enable_warnings(scripting_engine)


add_library(decompiler_engine STATIC
 src/backend/decompiler/DecompilerEngine.cpp
)
target_include_directories(decompiler_engine
 PUBLIC src
 PRIVATE "${RZ_GHIDRA_INCLUDE_DIR}"
)
target_link_libraries(decompiler_engine
 PUBLIC localization session_store Threads::Threads
 PRIVATE PkgConfig::RIZIN "${RZ_GHIDRA_LIBRARY}" ${BZIP2_LIBRARIES}
)
target_compile_definitions(
 decompiler_engine
  PRIVATE MYDBG_SLEIGH_HOME="${RZ_GHIDRA_SLEIGH_DIR}"
)
mydbg_enable_warnings(decompiler_engine)

add_executable(mydbg
  src/app/main.cpp
  src/app/App.cpp
  src/app/AppActions.cpp
  src/app/AppDrawing.cpp
  src/app/AppMenus.cpp
  src/app/ApplicationController.cpp
  src/app/DebuggerController.cpp
  src/app/DebuggerPanels.cpp
  src/app/DecompilerController.cpp
  src/app/DecompilerPanels.cpp
  src/app/DisassemblyGraph.cpp
  src/app/DisassemblyGraphLayout.cpp
  src/app/DisassemblyText.cpp
  src/app/DisassemblyTextDrawing.cpp
  src/app/GuiApplication.cpp
  src/app/Headless.cpp
  src/app/HelpContent.cpp
  src/app/HelpSystem.cpp
  src/app/MemoryData.cpp
  src/app/MemoryInspection.cpp
  src/app/MemoryPanels.cpp
  src/app/PythonController.cpp
  src/app/PythonPanels.cpp
  src/app/PythonSyntax.cpp
  src/app/ScriptRunner.cpp
  src/app/UiSmoke.cpp
  src/app/UiSupport.cpp
)
target_link_libraries(mydbg PRIVATE
  debugger_engine decompiler_engine scripting_engine imgui imgui_text_editor
  PNG::PNG
)
target_include_directories(mydbg PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}/generated"
)
target_include_directories(mydbg SYSTEM PRIVATE
  "${imgui_markdown_SOURCE_DIR}"
)
target_compile_definitions(mydbg PRIVATE
  MYDBG_MANUAL_ASSET_DIR="${CMAKE_CURRENT_SOURCE_DIR}/docs/manual"
  MYDBG_CTF_DEMO_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/examples/solve_ctf.py"
  MYDBG_CTF_CHALLENGE="$<TARGET_FILE:ctf_challenge>"
)
# Synchronize the generated bundle even when only screenshot assets changed.
add_custom_target(mydbg_manual_assets
  COMMAND ${CMAKE_COMMAND} -E rm -rf "$<TARGET_FILE_DIR:mydbg>/manual"
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    "${CMAKE_CURRENT_SOURCE_DIR}/docs/manual"
    "$<TARGET_FILE_DIR:mydbg>/manual"
  VERBATIM
)
add_dependencies(mydbg mydbg_manual_assets)
add_custom_command(TARGET mydbg POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    "${CMAKE_CURRENT_SOURCE_DIR}/locales"
    "$<TARGET_FILE_DIR:mydbg>/locales"
)
mydbg_configure_analysis_runtime(mydbg)
set_target_properties(mydbg PROPERTIES ENABLE_EXPORTS ON)
mydbg_enable_warnings(mydbg)

add_executable(crackme EXCLUDE_FROM_ALL examples/crackme.cpp)
mydbg_enable_warnings(crackme -g -O0 -fno-omit-frame-pointer)

add_executable(ctf_challenge examples/ctf_challenge.cpp)
mydbg_enable_warnings(ctf_challenge -g -O0 -fno-omit-frame-pointer)
add_dependencies(mydbg ctf_challenge)

include(CTest)
if(BUILD_TESTING)
  add_executable(memory_data_tests
    tests/memory_data.cpp src/app/MemoryData.cpp)
  target_include_directories(memory_data_tests PRIVATE src)
  mydbg_enable_warnings(memory_data_tests)
  add_test(NAME memory_data COMMAND memory_data_tests)
  add_executable(python_editor_tests
    tests/python_editor.cpp src/app/PythonSyntax.cpp)
  target_include_directories(python_editor_tests PRIVATE src)
  target_link_libraries(python_editor_tests PRIVATE imgui_text_editor)
  mydbg_enable_warnings(python_editor_tests)
  add_test(NAME python_editor COMMAND python_editor_tests)
  add_executable(localization_tests tests/localization.cpp)
  target_link_libraries(localization_tests PRIVATE localization)
  add_test(NAME localization COMMAND localization_tests)
  add_executable(session_store_tests tests/session_store.cpp)
  target_link_libraries(session_store_tests PRIVATE session_store Threads::Threads)
  mydbg_enable_warnings(session_store_tests)
  set_target_properties(session_store_tests PROPERTIES
    BUILD_RPATH "${RIZIN_LIBRARY_DIRS}")
  target_link_options(session_store_tests PRIVATE
    $<$<PLATFORM_ID:Linux>:-Wl,--disable-new-dtags>)
  add_test(NAME session_store COMMAND session_store_tests)
  find_program(LLDB_SERVER_EXECUTABLE NAMES lldb-server REQUIRED)
  find_program(MYDBG_CROSS_CLANG_EXECUTABLE NAMES clang-22 clang REQUIRED)
  find_program(MYDBG_LLD_EXECUTABLE NAMES ld.lld lld REQUIRED)
  find_program(QEMU_ARM_EXECUTABLE NAMES qemu-arm REQUIRED)
  find_program(QEMU_MIPSEL_EXECUTABLE NAMES qemu-mipsel REQUIRED)
  find_program(QEMU_PPC_EXECUTABLE NAMES qemu-ppc REQUIRED)
  foreach(fixture IN ITEMS basic condition attach interactive heap scans intelligence)
    add_executable(debuggee_${fixture} tests/debuggees/${fixture}.cpp)
    target_compile_options(debuggee_${fixture} PRIVATE
      -g -O0 -fno-omit-frame-pointer)
    if(NOT fixture STREQUAL "basic")
      mydbg_enable_warnings(debuggee_${fixture})
    endif()
  endforeach()
  add_executable(debuggee_crackme_x86_64
    tests/debuggees/crackme_x86_64.c
  )
  target_compile_options(debuggee_crackme_x86_64 PRIVATE
    -g -O0 -fno-omit-frame-pointer -fno-optimize-sibling-calls
    $<$<C_COMPILER_ID:Clang,GNU>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
  )
  add_executable(debuggee_rop_target tests/debuggees/rop_target.c)
  target_compile_options(debuggee_rop_target PRIVATE
    -g -O0 -fno-stack-protector -fno-omit-frame-pointer -no-pie
  )
  target_link_options(debuggee_rop_target PRIVATE -no-pie)
  add_executable(debuggee_symbolic_stdin tests/debuggees/symbolic_stdin.c)
  target_compile_options(debuggee_symbolic_stdin PRIVATE
    -g -O0 -fno-stack-protector -fno-omit-frame-pointer
  )
  add_executable(debuggee_keygenme tests/debuggees/keygenme.c)
  target_compile_options(debuggee_keygenme PRIVATE
    -g -O0 -fno-stack-protector -fno-omit-frame-pointer -no-pie
  )
  target_link_options(debuggee_keygenme PRIVATE -no-pie)

  set(MYDBG_CROSS_FIXTURE_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/cross-architecture-fixtures"
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
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/debuggees/crackme_${architecture}.c"
        -o "${fixture}"
      DEPENDS tests/debuggees/crackme_${architecture}.c
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

  add_executable(condition_language_tests
    tests/condition_language.cpp
    src/backend/conditions/BreakpointCondition.cpp
  )
  target_include_directories(condition_language_tests PRIVATE src)
  target_link_libraries(condition_language_tests PRIVATE localization)
  mydbg_enable_warnings(condition_language_tests)
  add_test(NAME condition_language COMMAND condition_language_tests)
  add_library(test_debugger_plugin MODULE
    tests/plugins/test_plugin.cpp
  )
  target_include_directories(test_debugger_plugin PRIVATE src)
  set_target_properties(test_debugger_plugin PROPERTIES
    PREFIX ""
  )
  mydbg_enable_warnings(test_debugger_plugin)
  add_test(
    NAME headless_keybindings
    COMMAND mydbg --headless-keybindings
  )
  add_test(
    NAME headless_vertical_slice
    COMMAND mydbg --headless $<TARGET_FILE:debuggee_basic>
      $<TARGET_FILE:debuggee_attach>
  )
  set_tests_properties(headless_vertical_slice PROPERTIES
    ENVIRONMENT
      "MYDBG_PLUGIN_PATH=$<TARGET_FILE_DIR:test_debugger_plugin>;MYDBG_REQUIRE_TEST_PLUGIN=1"
  )
  set_tests_properties(headless_vertical_slice PROPERTIES TIMEOUT 60)
  add_test(
    NAME headless_scripted_condition
    COMMAND mydbg --headless-condition
      $<TARGET_FILE:debuggee_condition>
  )
  set_tests_properties(
    headless_scripted_condition PROPERTIES TIMEOUT 20
  )
  add_test(
    NAME headless_glibc_heap
    COMMAND mydbg --headless-heap $<TARGET_FILE:debuggee_heap>
  )
  set_tests_properties(headless_glibc_heap PROPERTIES TIMEOUT 20)
  add_test(
    NAME headless_scans
    COMMAND mydbg --headless-scans $<TARGET_FILE:debuggee_scans>
  )
  set_tests_properties(headless_scans PROPERTIES TIMEOUT 30)
  add_test(
    NAME headless_stop_intelligence
    COMMAND mydbg --headless-intelligence
      $<TARGET_FILE:debuggee_intelligence>
  )
  set_tests_properties(headless_stop_intelligence PROPERTIES TIMEOUT 30)
  add_executable(python_lldb_coexistence_tests
    tests/python_lldb_coexistence.cpp
  )
  target_link_libraries(python_lldb_coexistence_tests
    PRIVATE debugger_engine pybind11::embed
  )
  mydbg_enable_warnings(python_lldb_coexistence_tests)
  mydbg_configure_analysis_runtime(python_lldb_coexistence_tests)
  add_test(
    NAME python_lldb_coexistence
    COMMAND python_lldb_coexistence_tests
  )
  set_tests_properties(python_lldb_coexistence PROPERTIES TIMEOUT 30)
  add_executable(lldb_engine_command_tests
    tests/lldb_engine_commands.cpp
  )
  target_link_libraries(lldb_engine_command_tests PRIVATE debugger_engine)
  mydbg_enable_warnings(lldb_engine_command_tests)
  mydbg_configure_analysis_runtime(lldb_engine_command_tests)
  add_test(
    NAME lldb_engine_commands
    COMMAND lldb_engine_command_tests $<TARGET_FILE:debuggee_basic>
  )
  set_tests_properties(lldb_engine_commands PROPERTIES
    TIMEOUT 30
    ENVIRONMENT "MYDBG_TRANSLATION=${CMAKE_CURRENT_SOURCE_DIR}/tests/locales/command_status.ini"
  )
  add_library(remote_process_harness STATIC
    tests/RemoteProcessHarness.cpp
  )
  target_link_libraries(remote_process_harness PUBLIC debugger_engine)
  mydbg_enable_warnings(remote_process_harness)

  add_executable(lldb_engine_remote_tests
    tests/lldb_engine_remote.cpp
  )
  target_link_libraries(lldb_engine_remote_tests
    PRIVATE remote_process_harness
  )
  mydbg_enable_warnings(lldb_engine_remote_tests)
  mydbg_configure_analysis_runtime(lldb_engine_remote_tests)
  add_test(
    NAME lldb_engine_remote
    COMMAND lldb_engine_remote_tests $<TARGET_FILE:debuggee_basic>
      "${LLDB_SERVER_EXECUTABLE}"
  )
  set_tests_properties(lldb_engine_remote PROPERTIES TIMEOUT 60)
  add_executable(lldb_engine_remote_lifecycle_tests
    tests/lldb_engine_remote_lifecycle.cpp
  )
  target_link_libraries(lldb_engine_remote_lifecycle_tests
    PRIVATE debugger_engine
  )
  mydbg_enable_warnings(lldb_engine_remote_lifecycle_tests)
  mydbg_configure_analysis_runtime(lldb_engine_remote_lifecycle_tests)
  add_test(
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

  add_library(debuggee_dwarf_library SHARED tests/debuggees/dwarf_library.cpp)
  target_compile_options(debuggee_dwarf_library PRIVATE
    -gdwarf-5 -O0 -fno-omit-frame-pointer)
  add_executable(dwarf_var_storage_tests tests/dwarf_var_storage.c)
  target_link_libraries(dwarf_var_storage_tests PRIVATE
    PkgConfig::RIZIN ${BZIP2_LIBRARIES})
  set_target_properties(dwarf_var_storage_tests PROPERTIES
    BUILD_RPATH "${RIZIN_LIBRARY_DIRS}")
  target_link_options(dwarf_var_storage_tests PRIVATE
    $<$<PLATFORM_ID:Linux>:-Wl,--disable-new-dtags>)
  add_test(NAME dwarf_var_storage COMMAND dwarf_var_storage_tests)
  set_source_files_properties(tests/debuggees/dwarf_secondary.cpp
    PROPERTIES COMPILE_OPTIONS "-O2")
  foreach(dwarf_version IN ITEMS 4 5)
    foreach(dwarf_layout IN ITEMS embedded split)
      set(dwarf_target "debuggee_dwarf${dwarf_version}_${dwarf_layout}")
      add_executable(${dwarf_target}
        tests/debuggees/dwarf.cpp tests/debuggees/dwarf_secondary.cpp)
      target_compile_options(${dwarf_target} PRIVATE
        "-gdwarf-${dwarf_version}" -O0 -fno-omit-frame-pointer -fPIE)
      target_link_options(${dwarf_target} PRIVATE -pie -Wl,--build-id=sha1)
      target_link_libraries(${dwarf_target} PRIVATE debuggee_dwarf_library)
      if(dwarf_layout STREQUAL "split")
        target_compile_options(${dwarf_target} PRIVATE -gsplit-dwarf)
      endif()
    endforeach()
  endforeach()

  add_executable(debuggee_session_exception tests/debuggees/session_exception.cpp)
  target_compile_options(debuggee_session_exception PRIVATE
    -g -O0 -fno-omit-frame-pointer)
  add_executable(session_persistence_tests tests/session_persistence.cpp)
  mydbg_configure_architecture_test(session_persistence_tests)
  add_dependencies(session_persistence_tests
    debuggee_dwarf5_embedded debuggee_session_exception)
  add_test(NAME session_persistence
    COMMAND session_persistence_tests $<TARGET_FILE:debuggee_dwarf5_embedded>
      $<TARGET_FILE:debuggee_session_exception>)
  set_tests_properties(session_persistence PROPERTIES TIMEOUT 90)

  set(MYDBG_DWARF_DEBUG_FILE "${CMAKE_CURRENT_BINARY_DIR}/dwarf.debug")
  set(MYDBG_DWARF_DEBUGLINK_FILE "${CMAKE_CURRENT_BINARY_DIR}/debuggee_dwarf_debuglink")
  set(MYDBG_DWARF_STRIPPED_FILE "${CMAKE_CURRENT_BINARY_DIR}/debuggee_dwarf_stripped")
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
  add_executable(dwarf_debug_info_tests tests/dwarf_debug_info.cpp)
  mydbg_configure_architecture_test(dwarf_debug_info_tests)
  add_dependencies(dwarf_debug_info_tests debuggee_dwarf_external
    debuggee_dwarf4_embedded debuggee_dwarf4_split debuggee_dwarf5_split)
  foreach(dwarf_version IN ITEMS 4 5)
    foreach(dwarf_layout IN ITEMS embedded split)
      add_test(NAME "dwarf${dwarf_version}_${dwarf_layout}"
        COMMAND dwarf_debug_info_tests
          "$<TARGET_FILE:debuggee_dwarf${dwarf_version}_${dwarf_layout}>"
          embedded)
      set_tests_properties("dwarf${dwarf_version}_${dwarf_layout}"
        PROPERTIES TIMEOUT 90)
    endforeach()
  endforeach()
  add_test(NAME dwarf_debuglink COMMAND dwarf_debug_info_tests
    "${MYDBG_DWARF_DEBUGLINK_FILE}" debuglink)
  add_test(NAME dwarf_explicit COMMAND dwarf_debug_info_tests
    "${MYDBG_DWARF_STRIPPED_FILE}" explicit "${MYDBG_DWARF_DEBUG_FILE}")
  add_test(NAME dwarf_stripped COMMAND dwarf_debug_info_tests
    "${MYDBG_DWARF_STRIPPED_FILE}" stripped)
  set_tests_properties(dwarf_debuglink dwarf_explicit dwarf_stripped
    PROPERTIES TIMEOUT 90)

  add_executable(lldb_engine_x86_64_tests
    tests/lldb_engine_x86_64.cpp
  )
  mydbg_configure_architecture_test(lldb_engine_x86_64_tests)
  add_dependencies(lldb_engine_x86_64_tests debuggee_crackme_x86_64)
  add_test(
    NAME robustness_x86_64
    COMMAND lldb_engine_x86_64_tests
      $<TARGET_FILE:debuggee_crackme_x86_64>
  )
  set_tests_properties(robustness_x86_64 PROPERTIES TIMEOUT 90)
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
      tests/lldb_engine_${architecture}.cpp)
    mydbg_configure_architecture_test(lldb_engine_${architecture}_tests)
    target_link_libraries(lldb_engine_${architecture}_tests
      PRIVATE remote_process_harness)
    add_dependencies(lldb_engine_${architecture}_tests
      debuggee_crackme_${architecture})
    add_test(NAME robustness_${architecture}
      COMMAND lldb_engine_${architecture}_tests
        "${MYDBG_${architecture_upper}_FIXTURE}" "${qemu}")
    set_tests_properties(robustness_${architecture} PROPERTIES
      TIMEOUT ${robustness_timeout})
  endforeach()


  add_executable(python_cross_arch_tests
    tests/python_cross_arch.cpp
  )
  target_link_libraries(python_cross_arch_tests PRIVATE scripting_engine)
  mydbg_enable_warnings(python_cross_arch_tests)
  mydbg_configure_analysis_runtime(python_cross_arch_tests)
  set_target_properties(python_cross_arch_tests PROPERTIES ENABLE_EXPORTS ON)
  add_dependencies(python_cross_arch_tests
    debuggee_crackme_x86_64
    debuggee_crackme_arm32
    debuggee_crackme_mips32
    debuggee_crackme_ppc32
  )
  set(MYDBG_CROSS_ARCH_SCRIPT
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/cross_arch_debugger.py"
  )
  add_test(
    NAME python_cross_x86_64
    COMMAND python_cross_arch_tests "${MYDBG_CROSS_ARCH_SCRIPT}"
      --native x86_64 $<TARGET_FILE:debuggee_crackme_x86_64> CTF!
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
    add_test(NAME python_cross_${architecture}
      COMMAND python_cross_arch_tests "${MYDBG_CROSS_ARCH_SCRIPT}"
        --qemu "${machine}" "${MYDBG_${architecture_upper}_FIXTURE}" "${qemu}")
    set_tests_properties(robustness_${architecture} python_cross_${architecture}
      PROPERTIES RESOURCE_LOCK qemu_${architecture})
  endforeach()
  set_tests_properties(
    python_cross_x86_64 python_cross_arm32 python_cross_mips32 python_cross_ppc32
    PROPERTIES TIMEOUT 120)
  add_executable(headless_remote_smoke_tests
    tests/headless_remote_smoke.cpp
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
    add_test(NAME actual_mydbg_${architecture}
      COMMAND "${Python_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/isolated_session.py"
        $<TARGET_FILE:headless_remote_smoke_tests> $<TARGET_FILE:mydbg>
        "${MYDBG_CROSS_ARCH_SCRIPT}" "${machine}"
        "${MYDBG_${architecture_upper}_FIXTURE}" "${qemu}")
    set_tests_properties(actual_mydbg_${architecture} PROPERTIES
      TIMEOUT 150 RESOURCE_LOCK qemu_${architecture})
  endforeach()
  add_executable(lldb_engine_scripting_tests
    tests/lldb_engine_scripting.cpp
  )
  target_link_libraries(lldb_engine_scripting_tests PRIVATE debugger_engine)
  mydbg_enable_warnings(lldb_engine_scripting_tests)
  mydbg_configure_analysis_runtime(lldb_engine_scripting_tests)
  add_test(
    NAME lldb_engine_scripting
    COMMAND lldb_engine_scripting_tests
      $<TARGET_FILE:debuggee_interactive>
      $<TARGET_FILE:debuggee_attach>
      $<TARGET_FILE_DIR:debuggee_interactive>
  )
  set_tests_properties(lldb_engine_scripting PROPERTIES TIMEOUT 45)
  add_executable(python_runtime_tests
    tests/python_runtime.cpp
  )
  target_link_libraries(python_runtime_tests PRIVATE scripting_engine)
  mydbg_enable_warnings(python_runtime_tests)
  mydbg_configure_analysis_runtime(python_runtime_tests)
  set_target_properties(python_runtime_tests PROPERTIES ENABLE_EXPORTS ON)
  add_test(
    NAME python_runtime
    COMMAND python_runtime_tests
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/integration.py"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/runtime_behaviors.py"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/failure.py"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/blocking.py"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/debuggable.py"
  )
  set_tests_properties(python_runtime PROPERTIES
    TIMEOUT 75
    ENVIRONMENT
      "MYDBG_TEST_INTERACTIVE=$<TARGET_FILE:debuggee_interactive>;MYDBG_TEST_WORKING_DIRECTORY=$<TARGET_FILE_DIR:debuggee_interactive>;MYDBG_TEST_ATTACH=$<TARGET_FILE:debuggee_attach>;MYDBG_TEST_BASIC=$<TARGET_FILE:debuggee_basic>"
  )
  add_test(
    NAME ctf_script_demo
    COMMAND "${Python_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/isolated_session.py"
      $<TARGET_FILE:mydbg> --headless-script
      "${CMAKE_CURRENT_SOURCE_DIR}/examples/solve_ctf.py"
  )
  set_tests_properties(ctf_script_demo PROPERTIES
    TIMEOUT 30
    ENVIRONMENT
      "MYDBG_CTF_CHALLENGE=$<TARGET_FILE:ctf_challenge>"
    PASS_REGULAR_EXPRESSION
      "flag\\{scripted_debuggers_turn_runtime_state_into_answers\\}"
  )
  add_test(
    NAME symbolic_script_x86_64
    COMMAND "${Python_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/symbolic_solver.py"
      --mydbg $<TARGET_FILE:mydbg>
      --script "${CMAKE_CURRENT_SOURCE_DIR}/examples/solve_symbolic.py"
      --target "$<TARGET_FILE:debuggee_crackme_x86_64>"
      --timeout-seconds 240
      --expect "crackme solved symbolically"
  )
  set_tests_properties(symbolic_script_x86_64 PROPERTIES
    TIMEOUT 420
    SKIP_RETURN_CODE 77
    PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
  )
  add_test(
    NAME rop_script_x86_64
    COMMAND "${Python_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/symbolic_solver.py"
      --mydbg $<TARGET_FILE:mydbg>
      --script "${CMAKE_CURRENT_SOURCE_DIR}/examples/rop_crackme.py"
      --target "$<TARGET_FILE:debuggee_rop_target>"
      --timeout-seconds 240
      --expect "rop-loop-ok"
  )
  set_tests_properties(rop_script_x86_64 PROPERTIES
    TIMEOUT 420
    SKIP_RETURN_CODE 77
    PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
  )
  add_test(
    NAME symbolic_script_stdin
    COMMAND "${Python_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/symbolic_solver.py"
      --mydbg $<TARGET_FILE:mydbg>
      --script "${CMAKE_CURRENT_SOURCE_DIR}/examples/solve_stdin.py"
      --target "$<TARGET_FILE:debuggee_symbolic_stdin>"
      --timeout-seconds 420
      --expect "stdin-solve-ok"
  )
  set_tests_properties(symbolic_script_stdin PROPERTIES
    TIMEOUT 600
    SKIP_RETURN_CODE 77
    PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
  )
  add_test(
    NAME symbolic_script_trace
    COMMAND "${Python_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/symbolic_solver.py"
      --mydbg $<TARGET_FILE:mydbg>
      --script "${CMAKE_CURRENT_SOURCE_DIR}/examples/solve_trace.py"
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
    add_test(
      NAME rop_emporium_${emporium_test}
      COMMAND "${Python_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/symbolic_solver.py"
        --mydbg $<TARGET_FILE:mydbg>
        --script "${CMAKE_CURRENT_SOURCE_DIR}/examples/rop_emporium/solve_${emporium_test}.py"
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
  add_test(
    NAME symbolic_script_keygen
    COMMAND "${Python_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/symbolic_solver.py"
      --mydbg $<TARGET_FILE:mydbg>
      --script "${CMAKE_CURRENT_SOURCE_DIR}/examples/solve_keygen.py"
      --target "$<TARGET_FILE:debuggee_keygenme>"
      --timeout-seconds 420
      --expect "keygen-solve-ok"
  )
  set_tests_properties(symbolic_script_keygen PROPERTIES
    TIMEOUT 600
    SKIP_RETURN_CODE 77
    PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
  )
  foreach(architecture IN ITEMS mips32 ppc32)
    string(TOUPPER "${architecture}" architecture_upper)
    if(architecture STREQUAL "mips32")
      set(qemu "${QEMU_MIPSEL_EXECUTABLE}")
      set(qemu_machine "mipsel")
      set(pointer_slot "")
    else()
      set(qemu "${QEMU_PPC_EXECUTABLE}")
      set(qemu_machine "ppc")
      # LLDB's function breakpoint lands after crackme_entry's prologue, which
      # has already moved the input pointer to the saved frame slot.
      set(pointer_slot "r31:24")
    endif()
    add_test(
      NAME symbolic_script_${architecture}
      COMMAND "${Python_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/symbolic_solver.py"
        --mydbg $<TARGET_FILE:mydbg>
        --script "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/symbolic_solve.py"
        --target "${MYDBG_${architecture_upper}_FIXTURE}"
        --qemu "${qemu}"
        --ptr-regs "a0,r4,r3"
        --ptr-slot "${pointer_slot}"
    )
    set_tests_properties(symbolic_script_${architecture} PROPERTIES
      TIMEOUT 600
      SKIP_RETURN_CODE 77
      PASS_REGULAR_EXPRESSION "symbolic-solver-ok"
      RESOURCE_LOCK qemu_${architecture}
    )
  endforeach()
endif()
