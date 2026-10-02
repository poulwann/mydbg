add_library(scripting_engine STATIC
  PythonHost.cpp
  PythonRuntime.cpp
  PythonRopTrace.cpp
  PythonBindings.cpp
  PythonBindingTypes.cpp
  PythonDebugger.cpp)
target_include_directories(scripting_engine
  PUBLIC "${PROJECT_SOURCE_DIR}/src"
  PRIVATE "${LLDB_INCLUDE_DIR}")
target_link_libraries(scripting_engine PUBLIC debugger_engine PRIVATE pybind11::embed)
target_compile_definitions(scripting_engine PRIVATE
  MYDBG_PYTHON_PACKAGE_DIR="${PROJECT_SOURCE_DIR}/python"
  MYDBG_LLDB_LLVM_VERSION_MAJOR=${MYDBG_LLDB_LLVM_VERSION_MAJOR})
mydbg_enable_warnings(scripting_engine)
