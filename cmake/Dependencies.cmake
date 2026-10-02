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
set(MYDBG_LLDB_LLVM_VERSION_MAJOR 0)
if(EXISTS "${LLDB_INCLUDE_DIR}/llvm/Config/llvm-config.h")
  file(READ "${LLDB_INCLUDE_DIR}/llvm/Config/llvm-config.h" MYDBG_LLVM_CONFIG_HEADER)
  string(REGEX MATCH "#define[ \t]+LLVM_VERSION_MAJOR[ \t]+([0-9]+)"
    MYDBG_LLVM_VERSION_MATCH "${MYDBG_LLVM_CONFIG_HEADER}")
  if(MYDBG_LLVM_VERSION_MATCH)
    set(MYDBG_LLDB_LLVM_VERSION_MAJOR "${CMAKE_MATCH_1}")
  endif()
endif()
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
