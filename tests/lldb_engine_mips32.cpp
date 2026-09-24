#include "backend/decompiler/DecompilerEngine.h"
#include "EngineTestSupport.h"
#include "RemoteProcessHarness.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <sstream>
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
using debugger::test::require;


debugger::CommandResult complete(debugger::CommandTicket ticket,
                                 std::chrono::milliseconds timeout,
                                 std::string_view operation) {
  require(ticket.valid(), std::string{operation} + " returned no ticket");
  require(ticket.wait_for(timeout),
          std::string{operation} + " did not complete");
  return ticket.get();
}

template <typename Predicate>
debugger::SessionSnapshot wait_for_state(
    debugger::LldbEngine &engine, debugger::SessionSnapshot current,
    std::chrono::milliseconds timeout, const Predicate &predicate) {
  return debugger::test::wait_for_state(
      engine, std::move(current), predicate, timeout,
      "timed out waiting for MIPS32 debugger state",
      "timed out waiting for MIPS32 debugger update");
}


void inspect_registers(Campaign &campaign, debugger::LldbEngine &engine,
                       const debugger::SessionSnapshot &state) {
  const debugger::RegisterValue *pc = find_register(state, "pc");
  const debugger::RegisterValue *sp = find_register(state, "sp");
  const debugger::RegisterValue *a0 = find_register(state, "a0");
  const debugger::RegisterValue *t0 = find_register(state, "t0");
  const debugger::RegisterValue *ra = find_register(state, "ra");

  campaign.expect(pc != nullptr && pc->has_numeric_value &&
                      pc->numeric_value == state.pc,
                  "frame-less register packet fallback did not publish pc");
  campaign.expect(sp != nullptr && sp->has_numeric_value &&
                      sp->numeric_value == state.sp && state.sp != 0,
                  "frame-less register packet fallback did not publish sp");
  campaign.expect(a0 != nullptr && a0->has_numeric_value,
                  "frame-less register packet fallback did not publish a0");
  campaign.expect(t0 != nullptr && t0->has_numeric_value,
                  "frame-less register packet fallback did not publish t0");
  campaign.expect(ra != nullptr && ra->has_numeric_value,
                  "frame-less register packet fallback did not publish ra");

  const std::array<std::pair<const char *, std::uint64_t>, 3> reads{{
      {"$pc", state.pc},
      {"$sp", state.sp},
      {"$a0", a0 != nullptr ? a0->numeric_value : 0},
  }};
  for (const auto &[name, expected] : reads) {
    const debugger::CommandResult result =
        complete(engine.read_register(name), 5s,
                 std::string{"read register "} + name);
    campaign.expect(result.success && result.has_numeric_value,
                    std::string{"typed native register read failed for "} +
                        name + ": " + result.message);
    if (result.success && result.has_numeric_value) {
      campaign.expect(result.numeric_value == expected,
                      std::string{"typed native register value disagreed for "} +
                          name);
    }
  }
}

void inspect_stop(Campaign &campaign, debugger::LldbEngine &engine,
                  const debugger::SessionSnapshot &state,
                  const std::filesystem::path &executable) {
  campaign.expect(state.mode == debugger::SessionMode::QemuUser,
                  "session did not retain the QEMU-user profile");
  campaign.expect(state.architecture.starts_with("mips"),
                  "snapshot architecture is not MIPS: " + state.architecture);
  campaign.expect(state.byte_order == "little",
                  "MIPS snapshot byte order is not little-endian");
  campaign.expect(state.address_byte_size == 4,
                  "MIPS32 snapshot does not use four-byte addresses");
  campaign.expect(!state.supports_intel_syntax,
                  "MIPS snapshot exposed the x86 syntax toggle");
  campaign.expect(state.pc != 0, "snapshot did not capture the program counter");
  campaign.expect(state.sp != 0, "snapshot did not capture the stack pointer");

  inspect_registers(campaign, engine, state);

  campaign.expect(!state.instructions.empty(),
                  "snapshot did not capture MIPS instructions");
  const bool contains_pc = std::any_of(
      state.instructions.begin(), state.instructions.end(),
      [&state](const debugger::InstructionRow &row) {
        return row.address == state.pc && !row.bytes.empty() &&
               !row.mnemonic.empty();
      });
  campaign.expect(contains_pc,
                  "instruction capture did not contain the stopped PC");
  const bool native_register_syntax = std::any_of(
      state.instructions.begin(), state.instructions.end(),
      [](const debugger::InstructionRow &row) {
        return row.operands.find('$') != std::string::npos;
      });
  campaign.expect(native_register_syntax,
                  "MIPS disassembly did not use native $register syntax");
  for (const debugger::InstructionRow &row : state.instructions) {
    campaign.expect(row.operands.find('%') == std::string::npos,
                    "MIPS disassembly used an x86 AT&T register prefix");
  }

  campaign.expect(!state.memory.empty(),
                  "snapshot did not capture memory at the stopped PC");
  const debugger::CommandResult bytes =
      complete(engine.read_memory(state.pc, 4), 5s, "read instruction memory");
  campaign.expect(bytes.success && bytes.bytes.size() == 4,
                  "typed memory read did not return one MIPS instruction");

  campaign.expect(!state.threads.empty(),
                  "snapshot did not capture the QEMU thread");
  const bool selected_thread = std::any_of(
      state.threads.begin(), state.threads.end(),
      [&state](const debugger::ThreadInfo &thread) {
        return thread.selected && thread.id == state.thread_id;
      });
  campaign.expect(selected_thread,
                  "thread capture did not identify the selected QEMU thread");

  const bool has_local_module =
      debugger::test::local_module(state, executable) != nullptr;
  campaign.expect(has_local_module,
                  "module capture did not retain the supplied local ELF");
}

struct Breakpoint final {
  std::string symbol;
  std::uint32_t id{};
  std::vector<std::uint64_t> addresses;
};

struct ChallengeBreakpoints final {
  Breakpoint entry;
  Breakpoint verify;
  Breakpoint mix;
  Breakpoint checkpoint;
  Breakpoint success;
  Breakpoint failure;

  [[nodiscard]] std::array<const Breakpoint *, 6> all() const {
    return {
        &entry, &verify, &mix, &checkpoint, &success, &failure,
    };
  }
};

constexpr std::size_t kMaximumCampaignInstructionSteps = 512;
constexpr std::size_t kMaximumTransitionInstructionSteps = 256;
constexpr std::size_t kMaximumTerminalFunctionInstructionSteps = 96;

struct InstructionBudget final {
  std::size_t remaining{kMaximumCampaignInstructionSteps};
  std::size_t completed{};
};

Breakpoint set_symbol_breakpoint(debugger::LldbEngine &engine,
                                 const char *symbol) {
  const debugger::SessionSnapshot previous = engine.snapshot();
  const std::size_t previous_count = previous.breakpoints.size();
  const debugger::CommandResult result =
      complete(engine.set_breakpoint(symbol), 5s,
               std::string{"set breakpoint "} + symbol);
  require(result.success,
          std::string{"unable to set breakpoint "} + symbol + ": " +
              result.message);
  const debugger::SessionSnapshot state = engine.snapshot();
  require(state.generation == previous.generation,
          std::string{"setting breakpoint changed generation for "} + symbol);
  require(state.revision > previous.revision,
          std::string{"setting breakpoint did not advance revision for "} +
              symbol);
  require(state.breakpoints.size() > previous_count,
          std::string{"breakpoint was not published for "} + symbol);
  const auto newest = std::max_element(
      state.breakpoints.begin(), state.breakpoints.end(),
      [](const debugger::BreakpointInfo &left,
         const debugger::BreakpointInfo &right) { return left.id < right.id; });
  require(newest != state.breakpoints.end() && newest->enabled,
          std::string{"breakpoint was not enabled for "} + symbol);
  require(newest->addresses.size() == 1,
          std::string{"breakpoint did not resolve to exactly one prologue for "} +
              symbol);
  return Breakpoint{.symbol = symbol,
                    .id = newest->id,
                    .addresses = newest->addresses};
}

ChallengeBreakpoints
set_challenge_breakpoints(debugger::LldbEngine &engine) {
  return ChallengeBreakpoints{
      .entry = set_symbol_breakpoint(engine, "crackme_entry"),
      .verify = set_symbol_breakpoint(engine, "crackme_verify"),
      .mix = set_symbol_breakpoint(engine, "crackme_mix"),
      .checkpoint = set_symbol_breakpoint(engine, "crackme_checkpoint"),
      .success = set_symbol_breakpoint(engine, "crackme_success"),
      .failure = set_symbol_breakpoint(engine, "crackme_failure"),
  };
}


std::string address_text(std::uint64_t address) {
  std::ostringstream stream;
  stream << "0x" << std::hex << address;
  return stream.str();
}

const debugger::BreakpointInfo *
find_published_breakpoint(const debugger::SessionSnapshot &state,
                          const Breakpoint &breakpoint) {
  const auto found = std::find_if(
      state.breakpoints.begin(), state.breakpoints.end(),
      [&breakpoint](const debugger::BreakpointInfo &candidate) {
        return candidate.id == breakpoint.id;
      });
  return found == state.breakpoints.end() ? nullptr : &*found;
}

std::uint32_t breakpoint_hit_count(
    const debugger::SessionSnapshot &state, const Breakpoint &breakpoint,
    std::string_view context) {
  const debugger::BreakpointInfo *published =
      find_published_breakpoint(state, breakpoint);
  require(published != nullptr,
          std::string{context} + " lost breakpoint " + breakpoint.symbol);
  return published->hit_count;
}

void require_breakpoint_stop(const debugger::SessionSnapshot &state,
                             const Breakpoint &breakpoint,
                             std::string_view context) {
  require(state.state == debugger::SessionState::Stopped,
          std::string{context} + " was not stopped at " + breakpoint.symbol);
  require(breakpoint.addresses.size() == 1,
          std::string{context} + " has an ambiguous prologue for " +
              breakpoint.symbol);
  require(state.pc == breakpoint.addresses.front(),
          std::string{context} + " stopped at " + address_text(state.pc) +
              " instead of the exact " + breakpoint.symbol +
              " prologue " + address_text(breakpoint.addresses.front()));
  require(breakpoint_hit_count(state, breakpoint, context) > 0U,
          std::string{context} + " recorded no synthetic/native hit for " +
              breakpoint.symbol);
}

const Breakpoint *
challenge_breakpoint_at(const ChallengeBreakpoints &breakpoints,
                        std::uint64_t pc) {
  for (const Breakpoint *breakpoint : breakpoints.all()) {
    if (breakpoint->addresses.size() == 1 &&
        breakpoint->addresses.front() == pc) {
      return breakpoint;
    }
  }
  return nullptr;
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
      [generation, revision,
       stop_revision](const debugger::SessionSnapshot &candidate) {
        if (candidate.generation != generation) {
          return true;
        }
        if (candidate.revision <= revision) {
          return false;
        }
        return (candidate.state == debugger::SessionState::Stopped &&
                candidate.stop_revision > stop_revision) ||
               candidate.state == debugger::SessionState::Exited ||
               candidate.state == debugger::SessionState::Error;
      });
  require(state.generation == generation,
          "generation changed while continuing to " + breakpoint.symbol);
  require(state.revision > revision,
          "revision did not advance while continuing to " + breakpoint.symbol);
  require(state.state == debugger::SessionState::Stopped,
          "target left the stopped state before " + breakpoint.symbol +
              " (PC " + address_text(state.pc) + ")");
  require(state.stop_revision > stop_revision,
          "stop revision did not advance at " + breakpoint.symbol);
  require_breakpoint_stop(state, breakpoint,
                          "continue to " + breakpoint.symbol);
  return state;
}

const debugger::InstructionRow *
instruction_at_pc(const debugger::SessionSnapshot &state) {
  const auto instruction = std::find_if(
      state.instructions.begin(), state.instructions.end(),
      [&state](const debugger::InstructionRow &row) {
        return row.address == state.pc;
      });
  return instruction == state.instructions.end() ? nullptr : &*instruction;
}

debugger::SessionSnapshot step_one_instruction(
    debugger::LldbEngine &engine, debugger::SessionSnapshot state,
    InstructionBudget &budget, std::string_view context) {
  require(state.state == debugger::SessionState::Stopped,
          std::string{context} + " cannot step from a non-stopped state");
  const debugger::InstructionRow *instruction = instruction_at_pc(state);
  require(instruction != nullptr && instruction->bytes.size() == 4,
          std::string{context} +
              " has no four-byte MIPS instruction at PC " +
              address_text(state.pc));
  require(budget.remaining > 0,
          std::string{context} + " exhausted the strict " +
              std::to_string(kMaximumCampaignInstructionSteps) +
              "-instruction campaign bound");

  const debugger::SessionSnapshot published = engine.snapshot();
  require(published.generation == state.generation &&
              published.stop_revision == state.stop_revision &&
              published.state == debugger::SessionState::Stopped &&
              published.pc == state.pc,
          std::string{context} +
              " observed debugger state drift before instruction step " +
              std::to_string(budget.completed + 1));

  const std::uint64_t generation = published.generation;
  const std::uint64_t revision = published.revision;
  const std::uint64_t stop_revision = published.stop_revision;
  const std::uint64_t pc = published.pc;
  --budget.remaining;
  ++budget.completed;
  const std::string operation =
      std::string{context} + " instruction step " +
      std::to_string(budget.completed);
  const debugger::CommandResult stepped =
      complete(engine.step_instruction(false), 5s, operation);
  require(stepped.success, operation + " failed: " + stepped.message);

  state = wait_for_state(
      engine, engine.snapshot(), 15s,
      [generation, revision,
       stop_revision](const debugger::SessionSnapshot &candidate) {
        if (candidate.generation != generation) {
          return true;
        }
        if (candidate.revision <= revision) {
          return false;
        }
        return (candidate.state == debugger::SessionState::Stopped &&
                candidate.stop_revision > stop_revision) ||
               candidate.state == debugger::SessionState::Exited ||
               candidate.state == debugger::SessionState::Error;
      });
  require(state.generation == generation,
          operation + " changed the inferior generation");
  require(state.revision > revision,
          operation + " did not publish a newer snapshot revision");
  require(state.state == debugger::SessionState::Stopped,
          operation + " did not publish a stopped snapshot (last PC " +
              address_text(state.pc) + ")");
  require(state.stop_revision > stop_revision,
          operation + " did not advance the stop revision");
  require(state.pc != pc,
          operation + " left PC unchanged at " + address_text(pc));
  return state;
}

debugger::SessionSnapshot step_to_breakpoint(
    debugger::LldbEngine &engine, debugger::SessionSnapshot state,
    const ChallengeBreakpoints &breakpoints, const Breakpoint &expected,
    InstructionBudget &budget, std::string_view context) {
  for (std::size_t transition_step = 0;
       transition_step < kMaximumTransitionInstructionSteps;
       ++transition_step) {
    state = step_one_instruction(engine, std::move(state), budget, context);
    const Breakpoint *reached =
        challenge_breakpoint_at(breakpoints, state.pc);
    if (reached == nullptr) {
      continue;
    }
    require(reached == &expected,
            std::string{context} + " reached unexpected prologue " +
                reached->symbol + " at " + address_text(state.pc) +
                " while seeking " + expected.symbol);
    require_breakpoint_stop(state, expected, context);
    return state;
  }
  require(false,
          std::string{context} + " did not reach " + expected.symbol +
              " within " +
              std::to_string(kMaximumTransitionInstructionSteps) +
              " instruction steps (last PC " + address_text(state.pc) + ")");
  return state;
}

debugger::SessionSnapshot step_through_terminal_function(
    debugger::LldbEngine &engine, debugger::SessionSnapshot state,
    const ChallengeBreakpoints &breakpoints, const Breakpoint &terminal,
    InstructionBudget &budget, std::string_view context) {
  require_breakpoint_stop(state, terminal, context);
  const debugger::RegisterValue *ra = find_register(state, "ra");
  require(ra != nullptr && ra->has_numeric_value && ra->numeric_value != 0,
          std::string{context} +
              " could not capture the terminal function return address");
  const std::uint64_t return_address = ra->numeric_value;

  for (std::size_t function_step = 0;
       function_step < kMaximumTerminalFunctionInstructionSteps;
       ++function_step) {
    state = step_one_instruction(engine, std::move(state), budget, context);
    if (state.pc == return_address) {
      return state;
    }
    const Breakpoint *reached =
        challenge_breakpoint_at(breakpoints, state.pc);
    require(reached == nullptr,
            std::string{context} + " reached unexpected prologue " +
                (reached != nullptr ? reached->symbol : std::string{}) +
                " while stepping through " + terminal.symbol);
  }
  require(false,
          std::string{context} + " did not step out of " + terminal.symbol +
              " to saved return address " + address_text(return_address) +
              " within " +
              std::to_string(kMaximumTerminalFunctionInstructionSteps) +
              " instruction steps");
  return state;
}

debugger::SessionSnapshot continue_to_exit(
    Campaign &campaign, debugger::LldbEngine &engine,
    debugger::SessionSnapshot state, int expected_status,
    std::string_view context) {
  const debugger::SessionSnapshot published = engine.snapshot();
  require(published.generation == state.generation &&
              published.stop_revision == state.stop_revision &&
              published.state == debugger::SessionState::Stopped &&
              published.pc == state.pc,
          std::string{context} +
              " observed debugger state drift before final continue");
  const std::uint64_t generation = published.generation;
  const std::uint64_t revision = published.revision;
  const debugger::CommandResult continued =
      complete(engine.continue_execution(), 5s,
               std::string{context} + " continue to exit");
  require(continued.success,
          std::string{context} +
              " final continue failed: " + continued.message);
  state = wait_for_state(
      engine, engine.snapshot(), 15s,
      [generation, revision](const debugger::SessionSnapshot &candidate) {
        return candidate.generation != generation ||
               (candidate.revision > revision &&
                (candidate.state == debugger::SessionState::Stopped ||
                 candidate.state == debugger::SessionState::Exited ||
                 candidate.state == debugger::SessionState::Error));
      });
  require(state.generation == generation,
          std::string{context} +
              " changed the inferior generation before exit");
  require(state.revision > revision,
          std::string{context} +
              " exit did not publish a newer snapshot revision");
  require(state.state == debugger::SessionState::Exited,
          std::string{context} + " did not terminate after final continue "
                                 "(last PC " +
              address_text(state.pc) + ")");
  campaign.expect(state.exit_status == expected_status,
                  std::string{context} + " exited with status " +
                      std::to_string(state.exit_status) + " instead of " +
                      std::to_string(expected_status));
  return state;
}

std::string module_id_for_executable(const debugger::SessionSnapshot &state,
                                     const std::filesystem::path &executable) {
  const auto *module = debugger::test::local_module(state, executable);
  if (module == nullptr) {
    return {};
  }
  return module->uuid.empty() ? module->path : module->uuid;
}

void inspect_decompilation(Campaign &campaign, debugger::LldbEngine &engine,
                           const debugger::SessionSnapshot &state,
                           const std::filesystem::path &executable) {
  campaign.expect(state.has_pc_file_address,
                  "stopped MIPS PC did not map to a local ELF address");
  const std::string module_id = module_id_for_executable(state, executable);
  campaign.expect(!module_id.empty(),
                  "local MIPS module has no stable decompiler identity");
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
      .debug_info_path = {},
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
                  "MIPS decompilation did not complete");
  if (!decompiled || decompiled->request_serial == 0 || decompiled->loading) {
    return;
  }
  campaign.expect(decompiled->error.empty(),
                  "MIPS decompilation failed: " + decompiled->error);
  campaign.expect(!decompiled->lines.empty(),
                  "MIPS decompilation returned no lines");
  campaign.expect(decompiled->module_id == module_id &&
                      decompiled->requested_load_address == state.pc &&
                      decompiled->requested_file_address ==
                          state.pc_file_address &&
                      decompiled->generation == state.generation,
                  "decompiler lost MIPS module/load/file address identity");
  campaign.expect(decompiled->function_min_file_address <=
                          state.pc_file_address &&
                      state.pc_file_address <
                          decompiled->function_max_file_address,
                  "decompiler selected a function that does not contain PC");
  const bool named_mix = std::any_of(
      decompiled->lines.begin(), decompiled->lines.end(),
      [](const debugger::DecompiledLine &line) {
        return line.text.find("crackme_mix") != std::string::npos;
      });
  campaign.expect(named_mix,
                  "decompiler did not identify the crackme_mix function");

  std::optional<std::uint64_t> mapped_file_address;
  for (const debugger::DecompiledLine &line : decompiled->lines) {
    if (!line.file_addresses.empty()) {
      mapped_file_address = line.file_addresses.front();
      break;
    }
  }
  campaign.expect(mapped_file_address.has_value(),
                  "decompiler lines carried no file-address mapping");
  if (mapped_file_address) {
    const std::uint64_t mapped_load_address =
        *mapped_file_address + state.pc_module_load_bias;
    const debugger::CommandResult result =
        complete(engine.read_instructions(mapped_load_address), 5s,
                 "map decompiler line to disassembly");
    campaign.expect(result.success, "mapped MIPS disassembly read failed");
    const debugger::SessionSnapshot mapped = engine.snapshot();
    campaign.expect(!mapped.instructions.empty() &&
                        mapped.instructions.front().address ==
                            mapped_load_address,
                    "decompiler file address did not map back to load address");
  }
}

void inspect_rejected_input(Campaign &campaign, const char *qemu,
                            const std::filesystem::path &executable,
                            const char *input, std::string_view description) {
  const std::string context =
      std::string{"rejected MIPS "} + std::string{description};
  QemuUserStub stub{qemu, executable.c_str(), input};
  debugger::LldbEngine engine;
  debugger::SessionSnapshot state = wait_for_state(
      engine, engine.snapshot(), 15s,
      [](const debugger::SessionSnapshot &candidate) {
        return candidate.state == debugger::SessionState::NoTarget;
      });
  state = debugger::test::connect_qemu_user(
      engine, stub, 15s, "connect " + context);

  const ChallengeBreakpoints breakpoints =
      set_challenge_breakpoints(engine);
  state = continue_to(engine, std::move(state), breakpoints.entry);

  InstructionBudget budget;
  state = step_to_breakpoint(engine, std::move(state), breakpoints,
                             breakpoints.verify, budget,
                             context + " entry-to-verify");
  state = step_to_breakpoint(engine, std::move(state), breakpoints,
                             breakpoints.mix, budget,
                             context + " verify-to-mix");
  state = step_to_breakpoint(engine, std::move(state), breakpoints,
                             breakpoints.checkpoint, budget,
                             context + " mix-to-checkpoint");
  state = step_to_breakpoint(engine, std::move(state), breakpoints,
                             breakpoints.failure, budget,
                             context + " checkpoint-to-failure");
  campaign.expect(
      breakpoint_hit_count(state, breakpoints.success, context) == 0U,
      context + " reached crackme_success");

  state = step_through_terminal_function(
      engine, std::move(state), breakpoints, breakpoints.failure, budget,
      context + " failure body");
  state = continue_to_exit(campaign, engine, std::move(state), 17, context);

  int qemu_status = 0;
  campaign.expect(stub.wait_for_exit(5s, qemu_status),
                  std::string{"qemu-mipsel did not exit for rejected "} +
                      std::string{description});
  if (WIFEXITED(qemu_status)) {
    campaign.expect(WEXITSTATUS(qemu_status) == 17,
                    std::string{"qemu-mipsel did not propagate status 17 for "} +
                        std::string{description});
  } else {
    campaign.expect(false, std::string{"qemu-mipsel did not exit normally for "} +
                               std::string{description});
  }
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s MIPS32_ELF QEMU_MIPSEL\n", argv[0]);
    return 2;
  }

  try {
    Campaign campaign{"MIPS32"};
    const std::filesystem::path executable{argv[1]};
    {
    QemuUserStub stub{argv[2], argv[1], "CTF!"};
    debugger::LldbEngine engine;
    debugger::SessionSnapshot state = wait_for_state(
        engine, engine.snapshot(), 15s,
        [](const debugger::SessionSnapshot &candidate) {
          return candidate.state == debugger::SessionState::NoTarget;
        });

    state = debugger::test::connect_qemu_user(engine, stub, 15s,
                                               "connect qemu-mipsel");
    inspect_stop(campaign, engine, state, executable);

    const ChallengeBreakpoints breakpoints =
        set_challenge_breakpoints(engine);
    state = continue_to(engine, std::move(state), breakpoints.entry);

    InstructionBudget budget;
    state = step_to_breakpoint(engine, std::move(state), breakpoints,
                               breakpoints.verify, budget,
                               "successful MIPS entry-to-verify");
    state = step_to_breakpoint(engine, std::move(state), breakpoints,
                               breakpoints.mix, budget,
                               "successful MIPS verify-to-mix");
    inspect_stop(campaign, engine, state, executable);
    inspect_decompilation(campaign, engine, state, executable);

    state = step_to_breakpoint(engine, std::move(state), breakpoints,
                               breakpoints.checkpoint, budget,
                               "successful MIPS mix-to-checkpoint");
    inspect_stop(campaign, engine, state, executable);
    state = step_to_breakpoint(engine, std::move(state), breakpoints,
                               breakpoints.success, budget,
                               "successful MIPS checkpoint-to-success");
    campaign.expect(
        breakpoint_hit_count(state, breakpoints.failure,
                             "successful MIPS path") == 0U,
        "successful CTF! input reached crackme_failure");

    state = step_through_terminal_function(
        engine, std::move(state), breakpoints, breakpoints.success, budget,
        "successful MIPS success body");
    state = continue_to_exit(campaign, engine, std::move(state), 0,
                             "successful MIPS path");

    int qemu_status = 0;
    campaign.expect(stub.wait_for_exit(5s, qemu_status),
                    "qemu-mipsel did not exit after the target exited");
    if (WIFEXITED(qemu_status)) {
      campaign.expect(WEXITSTATUS(qemu_status) == 0,
                      "qemu-mipsel propagated a nonzero target status");
    } else {
      campaign.expect(false, "qemu-mipsel did not exit normally");
    }
    }
    inspect_rejected_input(campaign, argv[2], executable, "NOPE",
                           "wrong input");
    inspect_rejected_input(campaign, argv[2], executable, nullptr,
                           "missing input");

    if (campaign.failures() != 0) {
      std::fprintf(stderr, "MIPS32 campaign found %d deficiencies\n",
                   campaign.failures());
      return 1;
    }
    std::printf("MIPS32 QEMU-user campaign passed\n");
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "MIPS32 campaign failure: %s\n", error.what());
    return 1;
  }
}
