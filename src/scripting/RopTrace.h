#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace debugger::scripting {

struct RopTraceRequest {
  std::uint64_t stack_address{};
  std::uint32_t stack_bytes{512};
  std::uint32_t max_instructions{256};
  std::uint32_t max_nodes{64};
  double timeout_seconds{5.0};
};

struct RopRegisterValue {
  std::string name;
  std::uint64_t value{};
};

struct RopRegisterChange {
  std::string name;
  std::uint64_t before{};
  std::uint64_t after{};
};

struct RopMemoryAccess {
  std::uint64_t address{};
  std::vector<std::uint8_t> before;
  std::vector<std::uint8_t> after;
  bool write{};
  bool stack{};
};

struct RopInstruction {
  std::uint64_t address{};
  std::uint64_t next_address{};
  std::uint64_t sp_before{};
  std::uint64_t sp_after{};
  std::vector<std::uint8_t> bytes;
  std::string text;
  std::string flow;
  bool completed{};
  std::vector<RopRegisterChange> register_changes;
  std::vector<RopMemoryAccess> memory_accesses;
};

// Occurrences, not unique code addresses: repeated gadgets retain distinct
// nodes.
struct RopNode {
  std::uint64_t entry_address{};
  std::uint64_t entry_sp{};
  std::optional<std::uint64_t> stack_slot;
  std::vector<RopInstruction> instructions;
};

struct RopStackSlot {
  std::uint64_t address{};
  std::uint64_t value{};
  bool readable{};
};

struct RopTrace {
  std::uint64_t generation{};
  std::uint64_t stop_revision{};
  std::uint64_t thread_id{};
  std::uint64_t source_pc{};
  std::uint64_t source_sp{};
  std::uint64_t stack_address{};
  std::uint32_t pointer_size{};
  std::string architecture;
  std::vector<RopRegisterValue> initial_registers;
  std::vector<RopStackSlot> stack_slots;
  std::vector<RopNode> nodes;
  std::string status;
  std::string message;
};

enum class RopJobStatus {
  Idle,
  Queued,
  Running,
  Cancelling,
  Succeeded,
  Failed,
  Cancelled
};

struct RopTraceSnapshot {
  std::uint64_t job_id{};
  RopJobStatus status{RopJobStatus::Idle};
  std::shared_ptr<const RopTrace> trace;
  std::string error;
};

} // namespace debugger::scripting
