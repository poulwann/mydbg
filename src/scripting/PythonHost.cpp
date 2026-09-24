#include "scripting/PythonHost.h"

#include <pybind11/embed.h>

#include <memory>

namespace py = pybind11;

namespace debugger::scripting {

struct PythonHost::Impl {
  Impl() {
    {
      py::module_ sys = py::module_::import("sys");
      sys.attr("path").attr("insert")(0, MYDBG_PYTHON_PACKAGE_DIR);
    }
    release = std::make_unique<py::gil_scoped_release>();
  }


  py::scoped_interpreter interpreter{};
  std::unique_ptr<py::gil_scoped_release> release;
};

PythonHost::PythonHost() : impl_(std::make_unique<Impl>()) {}
PythonHost::~PythonHost() = default;

} // namespace debugger::scripting
