#include "scripting/PythonRopTrace.h"
#include "localization/Localization.h"
#include "scripting/PythonBindings.h"

#include <pybind11/embed.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace py = pybind11;

namespace debugger::scripting {
namespace {

constexpr std::size_t maximum_trace_bytes = 64U * 1024U * 1024U;
constexpr std::size_t maximum_access_bytes = 65536;
constexpr std::size_t maximum_registers = 256;

[[noreturn]] void invalid_field(const char *name) {
  throw std::runtime_error(
      l10n::format(l10n::Key::RopRuntimeInvalidField, name));
}

py::handle field(const py::dict &value, const char *name) {
  PyObject *item = PyDict_GetItemString(value.ptr(), name);
  if (item == nullptr) {
    throw std::runtime_error(
        l10n::format(l10n::Key::RopRuntimeMissingField, name));
  }
  return py::handle{item};
}

py::dict dictionary(py::handle value, const char *name) {
  if (!PyDict_Check(value.ptr())) {
    invalid_field(name);
  }
  return py::reinterpret_borrow<py::dict>(value);
}

std::uint64_t number(py::handle value, const char *name) {
  if (!PyLong_Check(value.ptr()) || PyBool_Check(value.ptr())) {
    invalid_field(name);
  }
  const auto result = PyLong_AsUnsignedLongLong(value.ptr());
  if (PyErr_Occurred()) {
    PyErr_Clear();
    invalid_field(name);
  }
  return static_cast<std::uint64_t>(result);
}

std::uint64_t number(const py::dict &value, const char *name) {
  return number(field(value, name), name);
}

bool boolean(const py::dict &value, const char *name) {
  const py::handle item = field(value, name);
  if (!PyBool_Check(item.ptr())) {
    invalid_field(name);
  }
  return item.ptr() == Py_True;
}

// The Python simulator bounds execution and capture. Independently bound the
// returned representation before allocating native containers, so malformed
// Python values become a failed job rather than wrapping numbers or exhausting
// the UI's memory. The finished trace contains no Python-owned storage.
class TraceReader final {
public:
  explicit TraceReader(const RopTraceRequest &request)
      : request_(request), instructions_left_(request.max_instructions) {}

  std::shared_ptr<const RopTrace> read(py::handle value) {
    const py::dict data = dictionary(value, "trace");
    auto trace = std::make_shared<RopTrace>();
    trace->generation = number(data, "generation");
    trace->stop_revision = number(data, "stop_revision");
    trace->thread_id = number(data, "thread_id");
    trace->source_pc = number(data, "source_pc");
    trace->source_sp = number(data, "source_sp");
    trace->stack_address = number(data, "stack_address");
    if (trace->stack_address != request_.stack_address) {
      invalid_field("stack_address");
    }
    const std::uint64_t pointer_size = number(data, "pointer_size");
    if (pointer_size > std::numeric_limits<std::uint32_t>::max()) {
      invalid_field("pointer_size");
    }
    trace->pointer_size = static_cast<std::uint32_t>(pointer_size);
    trace->architecture = text(data, "architecture", 128);
    trace->initial_registers = sequence<RopRegisterValue>(
        field(data, "initial_registers"), "initial_registers",
        maximum_registers, [this](py::handle item) {
          const py::dict reg = dictionary(item, "initial_registers[]");
          return RopRegisterValue{.name = text(reg, "name", 128),
                                  .value = number(reg, "value")};
        });
    trace->stack_slots = sequence<RopStackSlot>(
        field(data, "stack_slots"), "stack_slots", maximum_trace_bytes,
        [](py::handle item) {
          const py::dict slot = dictionary(item, "stack_slots[]");
          return RopStackSlot{.address = number(slot, "address"),
                              .value = number(slot, "value"),
                              .readable = boolean(slot, "readable")};
        });
    trace->nodes =
        sequence<RopNode>(field(data, "nodes"), "nodes", request_.max_nodes,
                          [this](py::handle item) { return node(item); });
    // Failed capture and unsupported architectures still carry useful raw
    // provenance. Only an actual simulated x86 state requires a 4/8-byte ABI.
    if (pointer_size != 4 && pointer_size != 8 &&
        (!trace->nodes.empty() || !trace->initial_registers.empty())) {
      invalid_field("pointer_size");
    }
    trace->status = text(data, "status", 128);
    if (trace->status.empty()) {
      invalid_field("status");
    }
    trace->message = text(data, "message", 1024U * 1024U);
    return trace;
  }

private:
  void consume(std::size_t bytes) {
    if (bytes > bytes_left_) {
      throw std::runtime_error(l10n::text(l10n::Key::RopRuntimeResultTooLarge));
    }
    bytes_left_ -= bytes;
  }

  std::string text(const py::dict &value, const char *name,
                   std::size_t maximum) {
    const py::handle item = field(value, name);
    if (!PyUnicode_Check(item.ptr())) {
      invalid_field(name);
    }
    Py_ssize_t size{};
    const char *data = PyUnicode_AsUTF8AndSize(item.ptr(), &size);
    if (data == nullptr) {
      throw py::error_already_set{};
    }
    const auto length = static_cast<std::size_t>(size);
    if (length > maximum) {
      invalid_field(name);
    }
    consume(length);
    return std::string{data, length};
  }

  std::vector<std::uint8_t> bytes(const py::dict &value, const char *name,
                                  std::size_t maximum) {
    const py::handle item = field(value, name);
    if (!PyBytes_Check(item.ptr())) {
      invalid_field(name);
    }
    const auto length = static_cast<std::size_t>(PyBytes_Size(item.ptr()));
    if (length > maximum) {
      invalid_field(name);
    }
    consume(length);
    const auto *data =
        reinterpret_cast<const std::uint8_t *>(PyBytes_AsString(item.ptr()));
    return std::vector<std::uint8_t>{data, data + length};
  }

  template <typename T, typename Read>
  std::vector<T> sequence(py::handle value, const char *name,
                          std::size_t maximum, Read read) {
    if (!PyList_Check(value.ptr())) {
      invalid_field(name);
    }
    const auto length = static_cast<std::size_t>(PyList_Size(value.ptr()));
    if (length > maximum) {
      invalid_field(name);
    }
    if (length > bytes_left_ / sizeof(T)) {
      throw std::runtime_error(l10n::text(l10n::Key::RopRuntimeResultTooLarge));
    }
    consume(length * sizeof(T));
    std::vector<T> result;
    result.reserve(length);
    for (std::size_t index = 0; index < length; ++index) {
      result.push_back(read(py::handle{
          PyList_GetItem(value.ptr(), static_cast<Py_ssize_t>(index))}));
    }
    return result;
  }

  RopNode node(py::handle value) {
    const py::dict data = dictionary(value, "nodes[]");
    RopNode result;
    result.entry_address = number(data, "entry_address");
    result.entry_sp = number(data, "entry_sp");
    const py::handle slot = field(data, "stack_slot");
    if (!slot.is_none()) {
      result.stack_slot = number(slot, "stack_slot");
    }
    result.instructions = sequence<RopInstruction>(
        field(data, "instructions"), "instructions", instructions_left_,
        [this](py::handle item) { return instruction(item); });
    instructions_left_ -= result.instructions.size();
    return result;
  }

  RopInstruction instruction(py::handle value) {
    const py::dict data = dictionary(value, "instructions[]");
    RopInstruction result;
    result.address = number(data, "address");
    result.next_address = number(data, "next_address");
    result.sp_before = number(data, "sp_before");
    result.sp_after = number(data, "sp_after");
    result.bytes = bytes(data, "bytes", 15);
    result.text = text(data, "text", 4096);
    result.flow = text(data, "flow", 32);
    if (result.flow != "normal" && result.flow != "return" &&
        result.flow != "call" && result.flow != "jump" &&
        result.flow != "branch" && result.flow != "syscall" &&
        result.flow != "stop") {
      invalid_field("flow");
    }
    result.completed = boolean(data, "completed");
    result.register_changes = sequence<RopRegisterChange>(
        field(data, "register_changes"), "register_changes", maximum_registers,
        [this](py::handle item) {
          const py::dict reg = dictionary(item, "register_changes[]");
          return RopRegisterChange{.name = text(reg, "name", 128),
                                   .before = number(reg, "before"),
                                   .after = number(reg, "after")};
        });
    result.memory_accesses = sequence<RopMemoryAccess>(
        field(data, "memory_accesses"), "memory_accesses", maximum_trace_bytes,
        [this](py::handle item) {
          const py::dict access = dictionary(item, "memory_accesses[]");
          return RopMemoryAccess{
              .address = number(access, "address"),
              .before = bytes(access, "before", maximum_access_bytes),
              .after = bytes(access, "after", maximum_access_bytes),
              .write = boolean(access, "write"),
              .stack = boolean(access, "stack"),
          };
        });
    return result;
  }

  const RopTraceRequest &request_;
  std::size_t bytes_left_{maximum_trace_bytes};
  std::size_t instructions_left_;
};

} // namespace

std::shared_ptr<const RopTrace>
run_rop_trace(LldbEngine &engine, const RopTraceRequest &request,
              const std::shared_ptr<std::atomic_bool> &cancellation) {
  if (request.stack_bytes == 0 || request.stack_bytes > 65536 ||
      request.max_instructions == 0 || request.max_instructions > 10000 ||
      request.max_nodes == 0 || request.max_nodes > 4096 ||
      !std::isfinite(request.timeout_seconds) || request.timeout_seconds <= 0 ||
      request.timeout_seconds > 60) {
    throw std::runtime_error(l10n::text(l10n::Key::RopRuntimeInvalidRequest));
  }

  // Keep the catch inside the GIL scope: error_already_set owns Python
  // exception objects, so even exception formatting/destruction belongs here.
  py::gil_scoped_acquire acquire;
  try {
    if (cancellation->load()) {
      throw std::runtime_error(l10n::text(l10n::Key::RopRuntimeCancelled));
    }
    const py::object debugger = make_python_debugger(engine, cancellation);
    const py::object cancelled =
        py::cpp_function([cancellation] { return cancellation->load(); });
    const py::object value =
        py::module_::import("mydbg.rop_trace")
            .attr("trace_stack")(debugger, request.stack_address,
                                 py::arg("stack_bytes") = request.stack_bytes,
                                 py::arg("max_instructions") =
                                     request.max_instructions,
                                 py::arg("max_nodes") = request.max_nodes,
                                 py::arg("timeout") = request.timeout_seconds,
                                 py::arg("cancelled") = cancelled);
    return TraceReader{request}.read(value);
  } catch (const py::error_already_set &error) {
    throw std::runtime_error(
        l10n::format(l10n::Key::RopRuntimePythonFailure, error.what()));
  }
}

} // namespace debugger::scripting
