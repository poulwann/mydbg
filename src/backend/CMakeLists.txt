add_library(session_store STATIC session/SessionStore.cpp)
target_include_directories(session_store PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(session_store
  PUBLIC localization
  PRIVATE PkgConfig::RIZIN ${BZIP2_LIBRARIES})
mydbg_enable_warnings(session_store)

add_library(breakpoint_conditions STATIC conditions/BreakpointCondition.cpp)
target_include_directories(breakpoint_conditions PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(breakpoint_conditions PUBLIC localization)
mydbg_enable_warnings(breakpoint_conditions)

add_library(debugger_engine STATIC
  lldb/LldbEngine.cpp
  lldb/LldbSessions.cpp
  lldb/LldbEngineScanning.cpp
  lldb/LldbEngineSnapshots.cpp
  lldb/QemuProcess.cpp
  lldb/LldbRemoteArchitecture.cpp
  lldb/LldbInstructionCapture.cpp
  lldb/LldbInspectionCommands.cpp
  lldb/LldbHeapCommands.cpp
  lldb/LldbPatchCommands.cpp
  lldb/LldbFlowCommands.cpp
  lldb/LldbConsoleContext.cpp
  lldb/LldbEngineUtilities.cpp)
target_include_directories(debugger_engine
  PUBLIC "${PROJECT_SOURCE_DIR}/src"
  PRIVATE "${LLDB_INCLUDE_DIR}")
target_link_libraries(debugger_engine
  PUBLIC localization session_store debugger_plugins ${LLDB_LIBRARY} Threads::Threads
  PRIVATE breakpoint_conditions PkgConfig::RIZIN ${BZIP2_LIBRARIES})
mydbg_enable_warnings(debugger_engine)

add_library(decompiler_engine STATIC decompiler/DecompilerEngine.cpp)
target_include_directories(decompiler_engine
  PUBLIC "${PROJECT_SOURCE_DIR}/src"
  PRIVATE "${RZ_GHIDRA_INCLUDE_DIR}")
target_link_libraries(decompiler_engine
  PUBLIC localization session_store Threads::Threads
  PRIVATE PkgConfig::RIZIN "${RZ_GHIDRA_LIBRARY}" ${BZIP2_LIBRARIES})
target_compile_definitions(decompiler_engine
  PRIVATE MYDBG_SLEIGH_HOME="${RZ_GHIDRA_SLEIGH_DIR}")
mydbg_enable_warnings(decompiler_engine)
