#include "scripting/PythonBindings.h"
#include "localization/Localization.h"
#include "scripting/PythonBindingTypes.h"
#include "scripting/PythonDebugger.h"

#include <pybind11/embed.h>
#include <pybind11/stl.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace py = pybind11;

namespace debugger::scripting {
using detail::PythonDebugger;
using detail::PythonProcess;

namespace {
void register_mydbg_module(py::module_ &module) {
  module.def(
      "_text", [](const std::string &key) { return l10n::text_key(key); },
      py::arg("key"));
  detail::register_python_types(module);
  py::class_<PythonProcess, std::shared_ptr<PythonProcess>>(module, "Process")
      .def("send", &PythonProcess::send, py::arg("data"),
           py::arg("timeout") = 10.0)
      .def("sendline", &PythonProcess::sendline, py::arg("data") = py::bytes{},
           py::arg("timeout") = 10.0)
      .def("recv", &PythonProcess::recv, py::arg("size") = 4096,
           py::arg("timeout") = 10.0)
      .def("recvuntil", &PythonProcess::recvuntil, py::arg("delimiter"),
           py::arg("timeout") = 10.0);
  py::class_<PythonDebugger, std::shared_ptr<PythonDebugger>>(module,
                                                              "Debugger")
      .def("load", &PythonDebugger::load, py::arg("executable"),
           py::arg("timeout") = 10.0)
      .def("launch", &PythonDebugger::launch, py::arg("argv"),
           py::arg("stop_at") = "main",
           py::arg("environment") = std::map<std::string, std::string>{},
           py::arg("cwd") = "", py::arg("timeout") = 10.0,
           py::arg("stdin_path") = "")
      .def("attach", &PythonDebugger::attach, py::arg("process_id"),
           py::arg("timeout") = 10.0)
      .def("connect_remote", &PythonDebugger::connect_remote,
           py::arg("executable"), py::arg("endpoint"),
           py::arg("mode") = "qemu-user", py::arg("timeout") = 10.0,
           py::arg("qemu") = "", py::arg("sysroot") = "",
           py::arg("arguments") = std::vector<std::string>{},
           py::arg("cwd") = "", py::arg("stdin_file") = "")
      .def("restart", &PythonDebugger::restart, py::arg("timeout") = 10.0)
      .def("detach", &PythonDebugger::detach, py::arg("timeout") = 10.0)
      .def("terminate", &PythonDebugger::terminate, py::arg("timeout") = 10.0)
      .def("continue_execution", &PythonDebugger::continue_execution,
           py::arg("timeout") = 10.0)
      .def("continue_and_wait", &PythonDebugger::continue_and_wait,
           py::arg("timeout") = 10.0)
      .def("interrupt", &PythonDebugger::interrupt, py::arg("timeout") = 10.0)
      .def("interrupt_and_wait", &PythonDebugger::interrupt_and_wait,
           py::arg("timeout") = 10.0)
      .def("step_instruction", &PythonDebugger::step_instruction,
           py::arg("step_over") = false, py::arg("timeout") = 10.0)
      .def("run_to", &PythonDebugger::run_to, py::arg("address"),
           py::arg("timeout") = 10.0)
      .def("disassemble", &PythonDebugger::disassemble, py::arg("address"),
           py::arg("timeout") = 10.0)
      .def("wait_for_stop", &PythonDebugger::wait_for_stop,
           py::arg("timeout") = 10.0)
      .def("wait_for_exit", &PythonDebugger::wait_for_exit,
           py::arg("timeout") = 10.0)
      .def("snapshot", &PythonDebugger::snapshot)
      .def("evaluate", &PythonDebugger::evaluate, py::arg("expression"),
           py::arg("timeout") = 10.0)
      .def("read_register", &PythonDebugger::read_register, py::arg("name"),
           py::arg("timeout") = 10.0)
      .def("write_register", &PythonDebugger::write_register, py::arg("name"),
           py::arg("value"), py::arg("timeout") = 10.0)
      .def("read_memory", &PythonDebugger::read_memory, py::arg("address"),
           py::arg("size"), py::arg("timeout") = 10.0)
      .def("write_memory", &PythonDebugger::write_memory, py::arg("address"),
           py::arg("data"), py::arg("timeout") = 10.0)
      .def("select_thread", &PythonDebugger::select_thread,
           py::arg("thread_id"), py::arg("timeout") = 10.0)
      .def("select_frame", &PythonDebugger::select_frame, py::arg("thread_id"),
           py::arg("frame_index"), py::arg("timeout") = 10.0)
      .def("set_breakpoint", &PythonDebugger::set_breakpoint,
           py::arg("specification"), py::arg("timeout") = 10.0)
      .def("remove_breakpoint", &PythonDebugger::remove_breakpoint,
           py::arg("id"), py::arg("timeout") = 10.0)
      .def("enable_breakpoint", &PythonDebugger::enable_breakpoint,
           py::arg("id"), py::arg("enabled") = true, py::arg("timeout") = 10.0)
      .def("list_breakpoints", &PythonDebugger::list_breakpoints)
      .def("execute", &PythonDebugger::execute, py::arg("command"),
           py::arg("timeout") = 10.0);
}
} // namespace

void install_python_bindings() {
  py::module_ sys = py::module_::import("sys");
  py::dict modules = sys.attr("modules");
  if (modules.contains("_mydbg")) {
    return;
  }
  static PyModuleDef definition;
  py::module_ module =
      py::module_::create_extension_module("_mydbg", nullptr, &definition);
  register_mydbg_module(module);
  modules["_mydbg"] = module;
}

py::object
make_python_debugger(LldbEngine &engine,
                     std::shared_ptr<std::atomic_bool> cancellation) {
  py::module_::import("_mydbg");
  return py::cast(
      std::make_shared<PythonDebugger>(engine, std::move(cancellation)));
}

} // namespace debugger::scripting
