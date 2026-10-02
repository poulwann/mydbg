#include "scripting/PythonBindingTypes.h"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;

namespace debugger::scripting::detail {
namespace {

py::bytes python_bytes(const std::vector<std::uint8_t> &bytes) {
  return py::bytes{reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

} // namespace

void register_python_types(py::module_ &module) {
  py::class_<InstructionRow>(module, "Instruction")
      .def_readonly("address", &InstructionRow::address)
      .def_readonly("file_address", &InstructionRow::file_address)
      .def_readonly("has_file_address", &InstructionRow::has_file_address)
      .def_property_readonly("bytes",
                             [](const InstructionRow &instruction) {
                               return python_bytes(instruction.bytes);
                             })
      .def_readonly("mnemonic", &InstructionRow::mnemonic)
      .def_readonly("operands", &InstructionRow::operands)
      .def_readonly("comment", &InstructionRow::comment);
  py::class_<ModuleInfo>(module, "Module")
      .def_readonly("base", &ModuleInfo::base)
      .def_readonly("end", &ModuleInfo::end)
      .def_readonly("path", &ModuleInfo::path)
      .def_readonly("uuid", &ModuleInfo::uuid);
  py::class_<MemoryRegionInfo>(module, "MemoryRegion")
      .def_readonly("start", &MemoryRegionInfo::start)
      .def_readonly("end", &MemoryRegionInfo::end)
      .def_readonly("readable", &MemoryRegionInfo::readable)
      .def_readonly("writable", &MemoryRegionInfo::writable)
      .def_readonly("executable", &MemoryRegionInfo::executable)
      .def_readonly("name", &MemoryRegionInfo::name);
  py::class_<RegisterValue>(module, "RegisterValue")
      .def_readonly("name", &RegisterValue::name)
      .def_readonly("value", &RegisterValue::value);
  py::class_<StackFrameInfo>(module, "StackFrame")
      .def_readonly("thread_id", &StackFrameInfo::thread_id)
      .def_readonly("index", &StackFrameInfo::index)
      .def_readonly("selected", &StackFrameInfo::selected)
      .def_readonly("pc", &StackFrameInfo::pc)
      .def_readonly("sp", &StackFrameInfo::sp)
      .def_readonly("function", &StackFrameInfo::function)
      .def_readonly("module", &StackFrameInfo::module)
      .def_readonly("source_path", &StackFrameInfo::source_path)
      .def_readonly("source_line", &StackFrameInfo::source_line);
  py::class_<ThreadInfo>(module, "Thread")
      .def_readonly("id", &ThreadInfo::id)
      .def_readonly("index", &ThreadInfo::index)
      .def_readonly("selected", &ThreadInfo::selected)
      .def_readonly("name", &ThreadInfo::name)
      .def_readonly("stop_reason", &ThreadInfo::stop_reason)
      .def_readonly("frames", &ThreadInfo::frames);
  py::class_<BreakpointInfo>(module, "Breakpoint")
      .def_readonly("id", &BreakpointInfo::id)
      .def_readonly("enabled", &BreakpointInfo::enabled)
      .def_readonly("hit_count", &BreakpointInfo::hit_count)
      .def_readonly("description", &BreakpointInfo::description)
      .def_readonly("condition", &BreakpointInfo::condition)
      .def_readonly("addresses", &BreakpointInfo::addresses);
  py::class_<PatchInfo>(module, "Patch")
      .def_readonly("id", &PatchInfo::id)
      .def_readonly("address", &PatchInfo::address)
      .def_property_readonly(
          "original",
          [](const PatchInfo &patch) { return python_bytes(patch.original); })
      .def_property_readonly("replacement", [](const PatchInfo &patch) {
        return python_bytes(patch.replacement);
      });
  py::class_<CommandResult>(module, "CommandResult")
      .def_readonly("id", &CommandResult::id)
      .def_readonly("success", &CommandResult::success)
      .def_readonly("message", &CommandResult::message)
      .def_readonly("snapshot_revision", &CommandResult::snapshot_revision)
      .def_readonly("generation", &CommandResult::generation)
      .def_readonly("stop_revision", &CommandResult::stop_revision);
  py::class_<PythonExpressionResult>(module, "ExpressionResult")
      .def_readonly("value", &PythonExpressionResult::value)
      .def_readonly("type", &PythonExpressionResult::type)
      .def_readonly("summary", &PythonExpressionResult::summary)
      .def_readonly("numeric_value", &PythonExpressionResult::numeric_value);
  py::class_<PythonSnapshot>(module, "Snapshot")
      .def_readonly("state", &PythonSnapshot::state)
      .def_readonly("mode", &PythonSnapshot::mode)
      .def_readonly("revision", &PythonSnapshot::revision)
      .def_readonly("generation", &PythonSnapshot::generation)
      .def_readonly("stop_revision", &PythonSnapshot::stop_revision)
      .def_readonly("target_path", &PythonSnapshot::target_path)
      .def_readonly("target_triple", &PythonSnapshot::target_triple)
      .def_readonly("architecture", &PythonSnapshot::architecture)
      .def_readonly("byte_order", &PythonSnapshot::byte_order)
      .def_readonly("address_byte_size", &PythonSnapshot::address_byte_size)
      .def_readonly("supports_intel_syntax",
                    &PythonSnapshot::supports_intel_syntax)
      .def_readonly("intel_syntax", &PythonSnapshot::intel_syntax)
      .def_readonly("process_id", &PythonSnapshot::process_id)
      .def_readonly("thread_id", &PythonSnapshot::thread_id)
      .def_readonly("pc", &PythonSnapshot::pc)
      .def_readonly("sp", &PythonSnapshot::sp)
      .def_readonly("stop_reason", &PythonSnapshot::stop_reason)
      .def_readonly("error", &PythonSnapshot::error)
      .def_readonly("exit_status", &PythonSnapshot::exit_status)
      .def_readonly("registers", &PythonSnapshot::registers)
      .def_readonly("instructions", &PythonSnapshot::instructions)
      .def_readonly("breakpoints", &PythonSnapshot::breakpoints)
      .def_readonly("threads", &PythonSnapshot::threads)
      .def_readonly("modules", &PythonSnapshot::modules)
      .def_readonly("memory_regions", &PythonSnapshot::memory_regions)
      .def_readonly("patches", &PythonSnapshot::patches)
      .def_property_readonly("output", [](const PythonSnapshot &snapshot) {
        return py::bytes{snapshot.output};
      });
}

} // namespace debugger::scripting::detail
