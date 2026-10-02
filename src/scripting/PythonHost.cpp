#include "scripting/PythonHost.h"
#include "scripting/PythonBindings.h"
#include "backend/lldb/LldbEngine.h"



#include <pybind11/pybind11.h>

#include <memory>

namespace py = pybind11;

namespace debugger::scripting {

struct PythonHost::Impl {
  Impl() {
    if (Py_IsInitialized() == 0) {
#if MYDBG_LLDB_LLVM_VERSION_MAJOR > 0 && MYDBG_LLDB_LLVM_VERSION_MAJOR < 21
      initialize_lldb_runtime();
#endif
      if (Py_IsInitialized() == 0) {
        Py_InitializeEx(1);
        owns_interpreter = true;
        install_python_path_and_bindings();
        release = std::make_unique<py::gil_scoped_release>();
        return;
      }
    }

    py::gil_scoped_acquire acquire;
    install_python_path_and_bindings();
  }

  ~Impl() {
    release.reset();
    if (owns_interpreter) {
      Py_FinalizeEx();
    }
  }

  void install_python_path_and_bindings() {
    install_python_bindings();
    py::module_ sys = py::module_::import("sys");
    sys.attr("path").attr("insert")(0, MYDBG_PYTHON_PACKAGE_DIR);
  }

  bool owns_interpreter{};
  std::unique_ptr<py::gil_scoped_release> release;
};

PythonHost::PythonHost() : impl_(std::make_unique<Impl>()) {}
PythonHost::~PythonHost() = default;

} // namespace debugger::scripting
