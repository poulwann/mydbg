#include "backend/decompiler/DecompilerEngine.h"
#include "EngineTestSupport.h"
#include "RemoteProcessHarness.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <sys/wait.h>

using namespace std::chrono_literals;

namespace {
using debugger::test::QemuUserStub;

using debugger::test::Campaign;
using debugger::test::find_register;
using debugger::test::has_function;
using debugger::test::require;


debugger::CommandResult complete(debugger::CommandTicket ticket,
                                 std::chrono::milliseconds timeout,
                                 std::string_view operation) {
  require(ticket.valid(), std::string{operation} + " returned no ticket");
  require(ticket.wait_for(timeout), std::string{operation} + " timed out");
  return ticket.get();
}

template <typename Predicate>
debugger::SessionSnapshot wait_for_state(
    debugger::LldbEngine &engine, debugger::SessionSnapshot current,
    std::chrono::milliseconds timeout, const Predicate &predicate) {
  return debugger::test::wait_for_state(
      engine, std::move(current), predicate, timeout,
      "timed out waiting for ARM32 debugger state",
      "timed out waiting for ARM32 debugger update");
}

std::string lowercase(std::string text) {
  std::ranges::transform(text, text.begin(), [](unsigned char character) {
    return static_cast<char>(std::tolower(character));
  });
  return text;
}



void inspect_registers(Campaign &campaign, debugger::LldbEngine &engine,
                       const debugger::SessionSnapshot &state) {
  const debugger::RegisterValue *pc = find_register(state, "pc");
  const debugger::RegisterValue *sp = find_register(state, "sp");
  const debugger::RegisterValue *r0 = find_register(state, "r0");
  const debugger::RegisterValue *r4 = find_register(state, "r4");
  const debugger::RegisterValue *lr = find_register(state, "lr");

  campaign.expect(pc != nullptr && pc->has_numeric_value &&
                      pc->numeric_value == state.pc,
                  "register capture did not publish the ARM pc");
  campaign.expect(sp != nullptr && sp->has_numeric_value &&
                      sp->numeric_value == state.sp && state.sp != 0,
                  "register capture did not publish the ARM sp");
  campaign.expect(r0 != nullptr && r0->has_numeric_value,
                  "register capture did not publish ARM argument register r0");
  campaign.expect(r4 != nullptr && r4->has_numeric_value,
                  "register capture did not publish ARM callee-save register r4");
  campaign.expect(lr != nullptr && lr->has_numeric_value,
                  "register capture did not publish the ARM link register");

  const std::array<std::pair<const char *, std::uint64_t>, 3> reads{{
      {"$pc", state.pc},
      {"$sp", state.sp},
      {"$r0", r0 != nullptr ? r0->numeric_value : 0},
  }};
  for (const auto &[name, expected] : reads) {
    const debugger::CommandResult result =
        complete(engine.read_register(name), 5s,
                 std::string{"read register "} + name);
    campaign.expect(result.success && result.has_numeric_value,
                    std::string{"typed ARM register read failed for "} + name +
                        ": " + result.message);
    if (result.success && result.has_numeric_value) {
      campaign.expect(result.numeric_value == expected,
                      std::string{"typed ARM register value disagreed for "} +
                          name);
    }
  }
}

void inspect_stop(Campaign &campaign, debugger::LldbEngine &engine,
                  const debugger::SessionSnapshot &state,
                  const std::filesystem::path &executable) {
  const std::string architecture = lowercase(state.architecture);
  const std::string triple = lowercase(state.target_triple);
  campaign.expect(state.mode == debugger::SessionMode::QemuUser,
                  "session did not retain the QEMU-user profile");
  campaign.expect(architecture.find("arm") != std::string::npos &&
                      architecture.find("aarch64") == std::string::npos &&
                      architecture.find("arm64") == std::string::npos,
                  "snapshot architecture is not ARM32: " +
                      state.architecture);
  campaign.expect(triple.find("arm") != std::string::npos,
                  "target triple did not identify ARM: " +
                      state.target_triple);
  campaign.expect(state.byte_order == "little",
                  "ARM32 snapshot byte order is not little-endian");
  campaign.expect(state.address_byte_size == 4,
                  "ARM32 snapshot does not use four-byte addresses");
  campaign.expect(!state.supports_intel_syntax,
                  "ARM32 snapshot exposed the x86 syntax toggle");
  campaign.expect(state.pc != 0, "snapshot did not capture the program counter");
  campaign.expect(state.sp != 0, "snapshot did not capture the stack pointer");

  inspect_registers(campaign, engine, state);

  campaign.expect(!state.instructions.empty(),
                  "snapshot did not capture ARM instructions");
  const bool contains_pc = std::ranges::any_of(
      state.instructions, [&state](const debugger::InstructionRow &row) {
        return row.address == state.pc && row.bytes.size() == 4 &&
               !row.mnemonic.empty();
      });
  campaign.expect(contains_pc,
                  "instruction capture did not contain a four-byte ARM opcode "
                  "at the stopped PC");
  campaign.expect(std::ranges::all_of(
                      state.instructions,
                      [](const debugger::InstructionRow &row) {
                        return row.bytes.size() == 4 &&
                               row.operands.find('%') == std::string::npos &&
                               row.operands.find('$') == std::string::npos;
                      }),
                  "ARM-mode disassembly was not fixed-width native syntax");
  const bool native_mnemonic = std::ranges::any_of(
      state.instructions, [](const debugger::InstructionRow &row) {
        static constexpr std::array<std::string_view, 15> prefixes{
            "add", "sub", "mov", "ldr", "str", "push", "pop", "stm",
            "ldm", "eor", "cmp", "b",   "bl",  "svc",  "udf"};
        return std::ranges::any_of(prefixes, [&row](std::string_view prefix) {
          return row.mnemonic.starts_with(prefix);
        });
      });
  campaign.expect(native_mnemonic,
                  "ARM disassembly contained no architecture-native mnemonic");
  const bool native_operand = std::ranges::any_of(
      state.instructions, [](const debugger::InstructionRow &row) {
        return row.operands.find("r0") != std::string::npos ||
               row.operands.find("sp") != std::string::npos ||
               row.operands.find("lr") != std::string::npos;
      });
  campaign.expect(native_operand,
                  "ARM disassembly contained no native register spelling");

  campaign.expect(!state.memory.empty(),
                  "snapshot did not capture memory at the stopped PC");
  const debugger::CommandResult bytes =
      complete(engine.read_memory(state.pc, 4), 5s, "read ARM instruction");
  campaign.expect(bytes.success && bytes.bytes.size() == 4,
                  "typed memory read did not return one ARM instruction");
  campaign.expect(!state.memory_regions.empty(),
                  "QEMU-user stop did not publish ARM memory regions");

  campaign.expect(!state.threads.empty(),
                  "snapshot did not capture the QEMU ARM thread");
  const bool selected_thread = std::ranges::any_of(
      state.threads, [&state](const debugger::ThreadInfo &thread) {
        return thread.selected && thread.id == state.thread_id &&
               !thread.frames.empty();
      });
  campaign.expect(selected_thread,
                  "thread capture did not identify a selected ARM frame");

  const auto *module = debugger::test::local_module(state, executable, true);
  campaign.expect(module != nullptr,
                  "module capture did not retain the supplied ARM ELF");
  if (module != nullptr) {
    campaign.expect(module->end > module->base,
                    "ARM module did not publish a valid load range");
    const bool executable_pc_region = std::ranges::any_of(
        state.memory_regions,
        [&state, module](const debugger::MemoryRegionInfo &region) {
          return region.name == module->path && region.readable &&
                 region.executable && !region.writable &&
                 state.pc >= region.start && state.pc < region.end;
        });
    campaign.expect(executable_pc_region,
                    "ARM PC was not covered by the local ELF RX region");
    const bool writable_region = std::ranges::any_of(
        state.memory_regions,
        [module](const debugger::MemoryRegionInfo &region) {
          return region.name == module->path && region.readable &&
                 region.writable && !region.executable;
        });
    campaign.expect(writable_region,
                    "ARM local ELF did not publish an RW non-executable region");
  }
  campaign.expect(state.security.available,
                  "supplied ARM ELF metadata was not inspected");
  campaign.expect(!state.security.stripped,
                  "ARM crackme unexpectedly appeared stripped");
}

struct Breakpoint final {
  std::string symbol;
  std::uint32_t id{};
  std::uint64_t address{};
};

struct ChallengeBreakpoints final {
  Breakpoint entry;
  Breakpoint verify;
  Breakpoint mix;
  Breakpoint checkpoint;
  Breakpoint success;
  Breakpoint failure;
};

constexpr std::size_t kMaximumInstructionSteps = 512;

struct InstructionBudget final {
  std::size_t used{};
};

std::string address_text(std::uint64_t address) {
  char text[19]{};
  std::snprintf(text, sizeof(text), "0x%llx",
                static_cast<unsigned long long>(address));
  return text;
}

Breakpoint set_symbol_breakpoint(debugger::LldbEngine &engine,
                                 const char *symbol) {
  const std::size_t previous_count = engine.snapshot().breakpoints.size();
  const debugger::CommandResult result =
      complete(engine.set_breakpoint(symbol), 5s,
               std::string{"set breakpoint "} + symbol);
  require(result.success,
          std::string{"unable to set breakpoint "} + symbol + ": " +
              result.message);
  const debugger::SessionSnapshot state = engine.snapshot();
  require(state.breakpoints.size() > previous_count,
          std::string{"breakpoint was not published for "} + symbol);
  const auto newest = std::max_element(
      state.breakpoints.begin(), state.breakpoints.end(),
      [](const debugger::BreakpointInfo &left,
         const debugger::BreakpointInfo &right) { return left.id < right.id; });
  require(newest != state.breakpoints.end(),
          std::string{"breakpoint record was missing for "} + symbol);
  require(newest->enabled && newest->addresses.size() == 1,
          std::string{"breakpoint did not resolve to exactly one prologue for "} +
              symbol);
  require(newest->hit_count == 0,
          std::string{"new breakpoint already recorded a hit for "} + symbol);
  return Breakpoint{.symbol = symbol,
                    .id = newest->id,
                    .address = newest->addresses.front()};
}

ChallengeBreakpoints set_challenge_breakpoints(
    debugger::LldbEngine &engine) {
  return ChallengeBreakpoints{
      .entry = set_symbol_breakpoint(engine, "crackme_entry"),
      .verify = set_symbol_breakpoint(engine, "crackme_verify"),
      .mix = set_symbol_breakpoint(engine, "crackme_mix"),
      .checkpoint = set_symbol_breakpoint(engine, "crackme_checkpoint"),
      .success = set_symbol_breakpoint(engine, "crackme_success"),
      .failure = set_symbol_breakpoint(engine, "crackme_failure"),
  };
}

bool at_breakpoint(const debugger::SessionSnapshot &state,
                   const Breakpoint &breakpoint) {
  return state.pc == breakpoint.address;
}

const debugger::BreakpointInfo &published_breakpoint(
    const debugger::SessionSnapshot &state, const Breakpoint &breakpoint) {
  const auto found = std::ranges::find_if(
      state.breakpoints, [&breakpoint](const debugger::BreakpointInfo &value) {
        return value.id == breakpoint.id;
      });
  require(found != state.breakpoints.end(),
          "snapshot omitted breakpoint " + breakpoint.symbol);
  return *found;
}

void require_breakpoint_hit(const debugger::SessionSnapshot &state,
                            const Breakpoint &breakpoint) {
  require(state.state == debugger::SessionState::Stopped,
          "target was not stopped at " + breakpoint.symbol);
  require(at_breakpoint(state, breakpoint),
          "expected exact " + breakpoint.symbol + " prologue address " +
              address_text(breakpoint.address) + ", stopped at " +
              address_text(state.pc));
  const debugger::BreakpointInfo &published =
      published_breakpoint(state, breakpoint);
  require(published.enabled,
          "breakpoint became disabled at " + breakpoint.symbol);
  require(std::ranges::find(published.addresses, breakpoint.address) !=
              published.addresses.end(),
          "snapshot lost the resolved prologue address for " +
              breakpoint.symbol);
  require(published.hit_count > 0,
          "breakpoint hit count stayed zero at " + breakpoint.symbol);
}

const Breakpoint *challenge_breakpoint_at(
    const debugger::SessionSnapshot &state,
    const ChallengeBreakpoints &breakpoints) {
  const std::array<const Breakpoint *, 6> all{
      &breakpoints.entry,   &breakpoints.verify, &breakpoints.mix,
      &breakpoints.checkpoint, &breakpoints.success, &breakpoints.failure};
  const auto found = std::ranges::find_if(
      all, [&state](const Breakpoint *breakpoint) {
        return at_breakpoint(state, *breakpoint);
      });
  return found == all.end() ? nullptr : *found;
}

debugger::SessionSnapshot continue_to(debugger::LldbEngine &engine,
                                      debugger::SessionSnapshot state,
                                      const Breakpoint &breakpoint) {
  const std::uint64_t generation = state.generation;
  const std::uint64_t revision = state.revision;
  const std::uint64_t stop_revision = state.stop_revision;
  const debugger::CommandResult result =
      complete(engine.continue_execution(), 5s,
               "continue to " + breakpoint.symbol);
  require(result.success,
          "continue to " + breakpoint.symbol + " failed: " + result.message);
  state = wait_for_state(
      engine, engine.snapshot(), 15s,
      [generation, stop_revision](const debugger::SessionSnapshot &candidate) {
        return candidate.generation != generation ||
               (candidate.state == debugger::SessionState::Stopped &&
                candidate.stop_revision > stop_revision) ||
               candidate.state == debugger::SessionState::Exited ||
               candidate.state == debugger::SessionState::Error;
      });
  require(state.generation == generation,
          "target generation changed while continuing to " +
              breakpoint.symbol);
  require(state.revision > revision,
          "continue to " + breakpoint.symbol +
              " did not publish a newer snapshot revision");
  require(state.state == debugger::SessionState::Stopped,
          "target terminated before reaching " + breakpoint.symbol +
              (state.error.empty() ? std::string{} : ": " + state.error));
  require(state.stop_revision > stop_revision,
          "continue to " + breakpoint.symbol +
              " did not publish a new stopped snapshot");
  require_breakpoint_hit(state, breakpoint);
  return state;
}

debugger::SessionSnapshot step_once(debugger::LldbEngine &engine,
                                    debugger::SessionSnapshot state,
                                    InstructionBudget &budget,
                                    std::string_view destination) {
  require(state.state == debugger::SessionState::Stopped,
          "cannot instruction-step a target that is not stopped");
  require(budget.used < kMaximumInstructionSteps,
          "ARM instruction bound of " +
              std::to_string(kMaximumInstructionSteps) +
              " exhausted while stepping toward " +
              std::string{destination} + " at " + address_text(state.pc));

  const std::uint64_t generation = state.generation;
  const std::uint64_t revision = state.revision;
  const std::uint64_t stop_revision = state.stop_revision;
  const std::uint64_t pc = state.pc;
  const std::size_t step_number = ++budget.used;
  const std::string operation =
      "instruction-step toward " + std::string{destination} + " #" +
      std::to_string(step_number);
  const debugger::CommandResult result =
      complete(engine.step_instruction(false), 5s, operation);
  require(result.success, operation + " failed: " + result.message);

  state = wait_for_state(
      engine, engine.snapshot(), 15s,
      [generation, stop_revision](const debugger::SessionSnapshot &candidate) {
        return candidate.generation != generation ||
               (candidate.state == debugger::SessionState::Stopped &&
                candidate.stop_revision > stop_revision) ||
               candidate.state == debugger::SessionState::Exited ||
               candidate.state == debugger::SessionState::Error;
      });
  require(state.generation == generation,
          operation + " changed the target generation");
  require(state.revision > revision,
          operation + " did not publish a newer snapshot revision");
  require(state.state == debugger::SessionState::Stopped ||
              state.state == debugger::SessionState::Exited ||
              state.state == debugger::SessionState::Error,
          operation + " left the target in a nonterminal running state");
  if (state.state == debugger::SessionState::Stopped) {
    require(state.stop_revision > stop_revision,
            operation + " did not publish a new stopped snapshot");
    require(state.pc != pc,
            operation + " published a stop without advancing PC from " +
                address_text(pc));
  }
  return state;
}

debugger::SessionSnapshot step_to_breakpoint(
    debugger::LldbEngine &engine, debugger::SessionSnapshot state,
    const ChallengeBreakpoints &breakpoints, const Breakpoint &expected,
    InstructionBudget &budget) {
  require(state.state == debugger::SessionState::Stopped,
          "cannot traverse toward " + expected.symbol +
              " while the target is not stopped");
  require(!at_breakpoint(state, expected),
          "traversal toward " + expected.symbol +
              " started at its destination");
  const std::uint64_t generation = state.generation;
  const std::uint64_t revision = state.revision;
  const std::uint64_t stop_revision = state.stop_revision;

  for (;;) {
    state = step_once(engine, std::move(state), budget, expected.symbol);
    require(state.state == debugger::SessionState::Stopped,
            "target " +
                std::string{state.state == debugger::SessionState::Exited
                                ? "exited"
                                : "errored"} +
                " after instruction step " + std::to_string(budget.used) +
                " before reaching " + expected.symbol +
                (state.error.empty() ? std::string{} : ": " + state.error));
    const Breakpoint *reached =
        challenge_breakpoint_at(state, breakpoints);
    if (reached == nullptr) {
      continue;
    }
    require(reached->id == expected.id,
            "reached unexpected challenge prologue " + reached->symbol +
                " at " + address_text(state.pc) + " while stepping toward " +
                expected.symbol);
    require(state.generation == generation,
            "target generation changed while stepping to " + expected.symbol);
    require(state.revision > revision &&
                state.stop_revision > stop_revision,
            "traversal to " + expected.symbol +
                " did not advance snapshot and stop revisions");
    require_breakpoint_hit(state, expected);
    return state;
  }
}

void exercise_round_trips(Campaign &campaign, debugger::LldbEngine &engine) {
  debugger::CommandResult address =
      complete(engine.read_register("$r0"), 5s,
               "read checkpoint state pointer");
  campaign.expect(address.success && address.has_numeric_value &&
                      address.numeric_value != 0,
                  "checkpoint r0 did not expose crackme_state address");
  if (address.success && address.has_numeric_value &&
      address.numeric_value != 0) {
    debugger::CommandResult original =
        complete(engine.read_memory(address.numeric_value, 4), 5s,
                 "read crackme_state bytes");
    campaign.expect(original.success && original.bytes.size() == 4,
                    "unable to read the ARM writable state word");
    if (original.success && original.bytes.size() == 4) {
      campaign.expect(original.bytes ==
                          std::vector<std::uint8_t>{0xdf, 0x9b, 0x57, 0x13},
                      "ARM writable state did not expose little-endian initial "
                      "bytes");
      const std::vector<std::uint8_t> marker{0x78, 0x56, 0x34, 0x12};
      debugger::CommandResult written =
          complete(engine.write_memory(address.numeric_value, marker), 5s,
                   "write crackme_state bytes");
      campaign.expect(written.success,
                      "ARM target memory write failed: " + written.message);
      debugger::CommandResult read_back =
          complete(engine.read_memory(address.numeric_value, marker.size()), 5s,
                   "read back crackme_state bytes");
      campaign.expect(read_back.success && read_back.bytes == marker,
                      "ARM target memory round trip changed bytes");
      debugger::CommandResult restored =
          complete(engine.write_memory(address.numeric_value, original.bytes),
                   5s, "restore crackme_state bytes");
      campaign.expect(restored.success,
                      "ARM target memory could not be restored");
    }
  }

  debugger::CommandResult original_register =
      complete(engine.read_register("$r4"), 5s, "read ARM r4");
  campaign.expect(original_register.success &&
                      original_register.has_numeric_value,
                  "ARM register round trip could not read r4");
  if (original_register.success && original_register.has_numeric_value) {
    const std::uint64_t original = original_register.numeric_value & 0xffffffffU;
    const std::uint64_t marker = (original ^ 0x5a5a5a5aU) & 0xffffffffU;
    debugger::CommandResult written =
        complete(engine.write_register("$r4", marker), 5s, "write ARM r4");
    campaign.expect(written.success && written.has_numeric_value &&
                        written.numeric_value == marker,
                    "ARM register write did not publish the requested value");
    debugger::CommandResult read_back =
        complete(engine.read_register("$r4"), 5s, "read back ARM r4");
    campaign.expect(read_back.success && read_back.has_numeric_value &&
                        read_back.numeric_value == marker,
                    "ARM register round trip changed the r4 value");
    debugger::CommandResult restored =
        complete(engine.write_register("$r4", original), 5s,
                 "restore ARM r4");
    campaign.expect(restored.success,
                    "ARM register round trip could not restore r4");
  }
}

void inspect_decompilation(Campaign &campaign, debugger::LldbEngine &engine,
                           const debugger::SessionSnapshot &state,
                           const std::filesystem::path &executable) {
  campaign.expect(state.has_pc_file_address,
                  "stopped ARM PC did not map to a local ELF address");
  const auto *module = debugger::test::local_module(state, executable, true);
  const std::string module_id =
      module == nullptr ? std::string{}
                        : (module->uuid.empty() ? module->path : module->uuid);
  campaign.expect(!module_id.empty(),
                  "local ARM module has no stable decompiler identity");
  if (!state.has_pc_file_address || module_id.empty()) {
    return;
  }

  debugger::DecompilerEngine decompiler;
  decompiler.request(debugger::DecompilerRequest{
      .executable_path = executable.string(),
      .module_id = module_id,
      .file_address = state.pc_file_address,
      .load_address = state.pc,
      .generation = state.generation,
      .debug_info_path = module->debug_info_path,
  });

  std::shared_ptr<const debugger::DecompilerSnapshot> decompiled;
  const auto deadline = std::chrono::steady_clock::now() + 30s;
  while (std::chrono::steady_clock::now() < deadline) {
    decompiled = decompiler.snapshot();
    if (decompiled->request_serial != 0 && !decompiled->loading &&
        decompiled->generation == state.generation &&
        decompiled->requested_file_address == state.pc_file_address) {
      break;
    }
    std::this_thread::sleep_for(10ms);
  }
  campaign.expect(decompiled && decompiled->request_serial != 0 &&
                      !decompiled->loading,
                  "ARM decompilation did not complete");
  if (!decompiled || decompiled->request_serial == 0 || decompiled->loading) {
    return;
  }
  campaign.expect(decompiled->error.empty(),
                  "ARM decompilation failed: " + decompiled->error);
  campaign.expect(!decompiled->lines.empty(),
                  "ARM decompilation returned no lines");
  campaign.expect(decompiled->module_id == module_id &&
                      decompiled->requested_load_address == state.pc &&
                      decompiled->requested_file_address ==
                          state.pc_file_address &&
                      decompiled->generation == state.generation,
                  "decompiler lost ARM module/load/file address identity");
  campaign.expect(decompiled->function_min_file_address <=
                          state.pc_file_address &&
                      state.pc_file_address <
                          decompiled->function_max_file_address,
                  "decompiler selected a function that does not contain PC");
  const bool named_checkpoint = std::ranges::any_of(
      decompiled->lines, [](const debugger::DecompiledLine &line) {
        return line.text.find("crackme_checkpoint") != std::string::npos;
      });
  campaign.expect(named_checkpoint,
                  "decompiler did not identify crackme_checkpoint");

  std::optional<std::uint64_t> mapped_file_address;
  for (const debugger::DecompiledLine &line : decompiled->lines) {
    if (!line.file_addresses.empty()) {
      mapped_file_address = line.file_addresses.front();
      break;
    }
  }
  campaign.expect(mapped_file_address.has_value(),
                  "decompiler lines carried no ARM file-address mapping");
  if (mapped_file_address) {
    const std::uint64_t mapped_load_address =
        *mapped_file_address + state.pc_module_load_bias;
    const debugger::CommandResult result =
        complete(engine.read_instructions(mapped_load_address), 5s,
                 "map ARM decompiler line to disassembly");
    campaign.expect(result.success,
                    "mapped ARM disassembly read failed: " + result.message);
    const debugger::SessionSnapshot mapped = engine.snapshot();
    campaign.expect(!mapped.instructions.empty() &&
                        mapped.instructions.front().address ==
                            mapped_load_address,
                    "ARM decompiler file address did not map back to its load "
                    "address");
  }
}

debugger::SessionSnapshot connect(debugger::LldbEngine &engine,
                                  QemuUserStub &stub) {
  wait_for_state(engine, engine.snapshot(), 15s,
                 [](const debugger::SessionSnapshot &candidate) {
                   return candidate.state == debugger::SessionState::NoTarget;
                 });
  return debugger::test::connect_qemu_user(engine, stub, 20s,
                                           "connect qemu-arm");
}

void step_to_exit(Campaign &campaign, debugger::LldbEngine &engine,
                  debugger::SessionSnapshot state,
                  const ChallengeBreakpoints &breakpoints,
                  InstructionBudget &budget, int expected_status,
                  std::string_view description) {
  require(state.state == debugger::SessionState::Stopped,
          "cannot step " + std::string{description} +
              " final function while the target is not stopped");
  const std::uint64_t generation = state.generation;
  const std::uint64_t revision = state.revision;
  std::size_t stopped_steps = 0;

  for (;;) {
    state = step_once(engine, std::move(state), budget, description);
    if (state.state == debugger::SessionState::Stopped) {
      ++stopped_steps;
      const Breakpoint *reached =
          challenge_breakpoint_at(state, breakpoints);
      require(reached == nullptr,
              "stepping the final " + std::string{description} +
                  " function unexpectedly reached " +
                  (reached == nullptr ? std::string{"unknown"}
                                      : reached->symbol) +
                  " at " + address_text(state.pc));
      continue;
    }

    require(state.generation == generation,
            "target generation changed while stepping " +
                std::string{description} + " to exit");
    require(state.revision > revision,
            "stepping " + std::string{description} +
                " to exit did not advance the snapshot revision");
    campaign.expect(
        stopped_steps > 0,
        "final " + std::string{description} +
            " function did not publish an instruction-step stop");
    campaign.expect(
        state.state == debugger::SessionState::Exited,
        std::string{description} + " did not report exit" +
            (state.error.empty() ? std::string{} : ": " + state.error));
    if (state.state != debugger::SessionState::Exited) {
      return;
    }
    campaign.expect(state.exit_status == expected_status,
                    std::string{description} + " reported exit status " +
                        std::to_string(state.exit_status) + " instead of " +
                        std::to_string(expected_status));
    return;
  }
}

void exercise_success(Campaign &campaign, const char *qemu,
                      const std::filesystem::path &executable) {
  QemuUserStub stub{qemu, executable.c_str(), "CTF!"};
  debugger::LldbEngine engine;
  debugger::SessionSnapshot state =
      connect(engine, stub);
  inspect_stop(campaign, engine, state, executable);

  const ChallengeBreakpoints breakpoints =
      set_challenge_breakpoints(engine);
  state = engine.snapshot();
  InstructionBudget budget;

  state = continue_to(engine, std::move(state), breakpoints.entry);
  campaign.expect(has_function(state, "crackme_entry"),
                  "crackme_entry breakpoint had no symbolic ARM frame");

  const std::uint64_t entry_pc = state.pc;
  state = step_once(engine, std::move(state), budget, "crackme_verify");
  require(state.state == debugger::SessionState::Stopped,
          "ARM entry instruction step terminated before crackme_verify");
  campaign.expect(state.pc == entry_pc + 4,
                  "ARM-mode instruction step did not advance PC by four");
  campaign.expect(std::ranges::any_of(
                      state.instructions,
                      [&state](const debugger::InstructionRow &row) {
                        return row.address == state.pc;
                      }),
                  "ARM instruction step did not refresh disassembly at PC");

  state = step_to_breakpoint(engine, std::move(state), breakpoints,
                             breakpoints.verify, budget);
  state = step_to_breakpoint(engine, std::move(state), breakpoints,
                             breakpoints.mix, budget);
  inspect_stop(campaign, engine, state, executable);
  state = step_to_breakpoint(engine, std::move(state), breakpoints,
                             breakpoints.checkpoint, budget);
  campaign.expect(has_function(state, "crackme_checkpoint") &&
                      has_function(state, "crackme_mix") &&
                      has_function(state, "crackme_verify") &&
                      has_function(state, "crackme_entry"),
                  "checkpoint stop did not expose checkpoint/mix/verify/entry "
                  "nesting");
  campaign.expect(!state.stack.empty(),
                  "checkpoint stop did not expose ARM stack activity");
  inspect_stop(campaign, engine, state, executable);
  exercise_round_trips(campaign, engine);
  state = engine.snapshot();
  inspect_decompilation(campaign, engine, state, executable);
  state = engine.snapshot();

  state = step_to_breakpoint(engine, std::move(state), breakpoints,
                             breakpoints.success, budget);
  campaign.expect(!at_breakpoint(state, breakpoints.failure),
                  "successful CTF! input reached crackme_failure");
  campaign.expect(
      published_breakpoint(state, breakpoints.failure).hit_count == 0,
      "successful CTF! input recorded a crackme_failure breakpoint hit");
  campaign.expect(has_function(state, "crackme_success"),
                  "valid CTF! input did not reach crackme_success");
  step_to_exit(campaign, engine, std::move(state), breakpoints, budget, 0,
               "valid ARM input");

  int qemu_status = 0;
  campaign.expect(stub.wait_for_exit(5s, qemu_status),
                  "qemu-arm did not exit after the successful target exited");
  if (WIFEXITED(qemu_status)) {
    campaign.expect(WEXITSTATUS(qemu_status) == 0,
                    "qemu-arm propagated a nonzero successful status");
  } else {
    campaign.expect(false, "qemu-arm did not exit normally after success");
  }
}

void exercise_failure(Campaign &campaign, const char *qemu,
                      const std::filesystem::path &executable) {
  QemuUserStub stub{qemu, executable.c_str(), "NOPE"};
  debugger::LldbEngine engine;
  debugger::SessionSnapshot state =
      connect(engine, stub);
  const ChallengeBreakpoints breakpoints =
      set_challenge_breakpoints(engine);
  state = engine.snapshot();
  InstructionBudget budget;

  state = continue_to(engine, std::move(state), breakpoints.failure);
  campaign.expect(!at_breakpoint(state, breakpoints.success),
                  "invalid ARM input reached crackme_success");
  campaign.expect(has_function(state, "crackme_failure"),
                  "invalid ARM input did not reach crackme_failure");
  const std::array<const Breakpoint *, 5> unreachable{
      &breakpoints.entry, &breakpoints.verify, &breakpoints.mix,
      &breakpoints.checkpoint, &breakpoints.success};
  for (const Breakpoint *breakpoint : unreachable) {
    campaign.expect(
        published_breakpoint(state, *breakpoint).hit_count == 0,
        "invalid ARM wrapper unexpectedly reached " + breakpoint->symbol);
  }
  step_to_exit(campaign, engine, std::move(state), breakpoints, budget, 17,
               "invalid ARM input");

  int qemu_status = 0;
  campaign.expect(stub.wait_for_exit(5s, qemu_status),
                  "qemu-arm did not exit after the rejected target exited");
  if (WIFEXITED(qemu_status)) {
    campaign.expect(WEXITSTATUS(qemu_status) == 17,
                    "qemu-arm did not propagate rejected status 17");
  } else {
    campaign.expect(false, "qemu-arm did not exit normally after rejection");
  }
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s ARM32_ELF QEMU_ARM\n", argv[0]);
    return 2;
  }

  try {
    Campaign campaign{"ARM32"};
    const std::filesystem::path executable{argv[1]};
    exercise_success(campaign, argv[2], executable);
    exercise_failure(campaign, argv[2], executable);
    if (campaign.failures() != 0) {
      std::fprintf(stderr, "ARM32 campaign found %d deficiencies\n",
                   campaign.failures());
      return 1;
    }
    std::printf("ARM32 QEMU-user campaign passed\n");
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "ARM32 campaign failure: %s\n", error.what());
    return 1;
  }
}
