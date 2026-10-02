cmake_minimum_required(VERSION 3.28)

project(mydbg VERSION 0.5 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")

include(GNUInstallDirs)

include(CTest)
include(cmake/Dependencies.cmake)
include(cmake/Resources.cmake)

function(mydbg_enable_warnings target)
  target_compile_options(${target} PRIVATE ${ARGN}
    $<$<CXX_COMPILER_ID:Clang,GNU>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>)
endfunction()

function(mydbg_configure_analysis_runtime target)
  set_target_properties(${target} PROPERTIES
    BUILD_RPATH "${RZ_GHIDRA_PLUGIN_DIR};${RIZIN_LIBRARY_DIRS}"
    INSTALL_RPATH "$ORIGIN/deps/lib;$ORIGIN/deps/lib64;$ORIGIN/deps/lib/rizin/plugins"
    INSTALL_RPATH_USE_LINK_PATH FALSE)
  target_link_options(${target} PRIVATE
    $<$<PLATFORM_ID:Linux>:-Wl,--disable-new-dtags>)
endfunction()

include(cmake/GuiLibraries.cmake)
add_subdirectory(src/localization)
add_subdirectory(src/plugins)
add_subdirectory(src/backend)
add_subdirectory(src/scripting)
add_subdirectory(examples)
add_subdirectory(src/app)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

include(cmake/Packaging.cmake)
