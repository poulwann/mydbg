#pragma once

#include "backend/DebuggerTypes.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pybind11 {
class module_;
}

namespace debugger::scripting::detail {

struct PythonSnapshot {
  explicit PythonSnapshot(const SessionSnapshot &snapshot)
      : state(to_string(snapshot.state)), mode(to_string(snapshot.mode)),
        revision(snapshot.revision), generation(snapshot.generation),
        stop_revision(snapshot.stop_revision),
        target_path(snapshot.target_path),
        target_triple(snapshot.target_triple),
        architecture(snapshot.architecture), byte_order(snapshot.byte_order),
        address_byte_size(snapshot.address_byte_size),
        supports_intel_syntax(snapshot.supports_intel_syntax),
        intel_syntax(snapshot.intel_syntax), process_id(snapshot.process_id),
        thread_id(snapshot.thread_id), pc(snapshot.pc), sp(snapshot.sp),
        stop_reason(snapshot.stop_reason), error(snapshot.error),
        exit_status(snapshot.exit_status), registers(snapshot.registers),
        instructions(snapshot.instructions), breakpoints(snapshot.breakpoints),
        threads(snapshot.threads), modules(snapshot.modules),
        memory_regions(snapshot.memory_regions), patches(snapshot.patches),
        output(snapshot.process_output) {}

  std::string state;
  std::string mode;
  std::uint64_t revision{};
  std::uint64_t generation{};
  std::uint64_t stop_revision{};
  std::string target_path;
  std::string target_triple;
  std::string architecture;
  std::string byte_order;
  std::uint32_t address_byte_size{};
  bool supports_intel_syntax{};
  bool intel_syntax{};
  std::uint64_t process_id{};
  std::uint64_t thread_id{};
  std::uint64_t pc{};
  std::uint64_t sp{};
  std::string stop_reason;
  std::string error;
  int exit_status{};
  std::vector<RegisterValue> registers;
  std::vector<InstructionRow> instructions;
  std::vector<BreakpointInfo> breakpoints;
  std::vector<ThreadInfo> threads;
  std::vector<ModuleInfo> modules;
  std::vector<MemoryRegionInfo> memory_regions;
  std::vector<PatchInfo> patches;
  std::string output;
};

struct PythonExpressionResult {
  std::string value;
  std::string type;
  std::string summary;
  std::optional<std::uint64_t> numeric_value;
};

void register_python_types(pybind11::module_ &module);

} // namespace debugger::scripting::detail
