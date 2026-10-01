add_library(memory_data STATIC MemoryData.cpp)
target_include_directories(memory_data PUBLIC "${PROJECT_SOURCE_DIR}/src")
mydbg_enable_warnings(memory_data)

add_library(app_ui STATIC
  AppActions.cpp
  AppDrawing.cpp
  AppMenus.cpp
  ApplicationController.cpp
  DebuggerController.cpp
  DebuggerPanels.cpp
  DecompilerController.cpp
  DecompilerPanels.cpp
  DisassemblyGraph.cpp
  DisassemblyGraphLayout.cpp
  DisassemblyText.cpp
  DisassemblyTextDrawing.cpp
  GuiApplication.cpp
  HelpContent.cpp
  HelpSystem.cpp
  MemoryController.cpp
  MemoryInspection.cpp
  MemoryPanels.cpp
  PythonController.cpp
  PythonPanels.cpp
  PythonState.cpp
  PythonSyntax.cpp
  UiSupport.cpp
)
target_link_libraries(app_ui
  PUBLIC debugger_engine decompiler_engine scripting_engine imgui imgui_text_editor memory_data
  PRIVATE PNG::PNG breakpoint_conditions)
target_include_directories(app_ui PRIVATE "${PROJECT_BINARY_DIR}/generated")
target_include_directories(app_ui SYSTEM PRIVATE "${imgui_markdown_SOURCE_DIR}")
target_compile_definitions(app_ui PRIVATE
  MYDBG_MANUAL_ASSET_DIR="${PROJECT_SOURCE_DIR}/docs/manual"
  MYDBG_CTF_DEMO_SCRIPT="${PROJECT_SOURCE_DIR}/examples/solve_ctf.py")
mydbg_enable_warnings(app_ui)

add_executable(mydbg main.cpp App.cpp ScriptRunner.cpp)
target_link_libraries(mydbg PRIVATE app_ui)
target_compile_definitions(mydbg PRIVATE
  MYDBG_CTF_CHALLENGE="$<TARGET_FILE:ctf_challenge>")
add_dependencies(mydbg ctf_challenge)
mydbg_configure_analysis_runtime(mydbg)
set_target_properties(mydbg PROPERTIES ENABLE_EXPORTS ON)
mydbg_enable_warnings(mydbg)

# Synchronize the generated bundle even when only screenshot assets changed.
add_custom_target(mydbg_manual_assets
  COMMAND ${CMAKE_COMMAND} -E rm -rf "$<TARGET_FILE_DIR:mydbg>/manual"
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    "${PROJECT_SOURCE_DIR}/docs/manual" "$<TARGET_FILE_DIR:mydbg>/manual"
  VERBATIM)
add_dependencies(mydbg mydbg_manual_assets)
add_custom_command(TARGET mydbg POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    "${PROJECT_SOURCE_DIR}/locales" "$<TARGET_FILE_DIR:mydbg>/locales")
