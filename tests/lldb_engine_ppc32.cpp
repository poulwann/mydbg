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
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>


using namespace std::chrono_literals;

namespace {
using debugger::test::QemuUserStub;

using debugger::test::fail;
using debugger::test::has_function;
using debugger::test::require;

debugger::CommandResult complete(debugger::CommandTicket ticket,
                                 std::chrono::milliseconds timeout,
                                 std::string_view operation) {
  require(ticket.wait_for(timeout), std::string{operation} + " timed out");
  debugger::CommandResult result = ticket.get();
  require(result.success, std::string{operation} + " failed: " + result.message);
  return result;
}

template <typename Predicate>
debugger::SessionSnapshot wait_for_state(
    debugger::LldbEngine &engine, debugger::SessionSnapshot current,
    const Predicate &predicate, std::chrono::milliseconds timeout = 20s) {
  return debugger::test::wait_for_state(
      engine, std::move(current), predicate, timeout,
      "timed out waiting for debugger state",
      "timed out waiting for debugger update");
}


bool architecture_is_powerpc(std::string architecture) {
  std::ranges::transform(architecture, architecture.begin(),
                         [](unsigned char character) {
                           return static_cast<char>(std::tolower(character));
                         });
  return architecture.find("powerpc") != std::string::npos ||
         architecture.find("ppc") != std::string::npos;
}



const debugger::ModuleInfo &local_module(const debugger::SessionSnapshot &state,
                                         const char *executable) {
  const std::filesystem::path requested{executable};
  const auto module = std::ranges::find_if(
      state.modules, [&requested](const debugger::ModuleInfo &candidate) {
        if (candidate.path == requested.string()) {
          return true;
        }
        return std::filesystem::path{candidate.path}.filename() ==
               requested.filename();
      });
  require(module != state.modules.end(),
          "remote snapshot did not retain the local PowerPC ELF module");
  return *module;
}

void require_powerpc_snapshot(const debugger::SessionSnapshot &state,
                              const char *executable) {
  require(state.mode == debugger::SessionMode::QemuUser,
          "remote session did not retain QEMU-user mode");
  require(architecture_is_powerpc(state.architecture),
          "snapshot did not identify a PowerPC architecture: " +
              state.architecture);
  require(state.byte_order == "big",
          "PowerPC snapshot did not report big-endian byte order");
  require(state.address_byte_size == 4,
          "PowerPC snapshot did not report a 32-bit address size");
  require(!state.supports_intel_syntax,
          "PowerPC snapshot incorrectly exposed the x86 syntax switch");
  require(state.pc != 0 && state.sp != 0,
          "PowerPC PC or stack pointer was not captured");
  require(debugger::test::find_register(state, "r1") &&
              debugger::test::find_register(state, "r3") &&
              debugger::test::find_register(state, "pc") &&
              debugger::test::find_register(state, "lr"),
          "PowerPC native r1/r3/pc/lr registers were not published");
  require(!state.instructions.empty(),
          "PowerPC instructions were not disassembled");
  require(std::ranges::all_of(
              state.instructions,
              [](const debugger::InstructionRow &instruction) {
                return instruction.bytes.size() == 4 &&
                       instruction.operands.find('%') == std::string::npos;
              }),
          "PowerPC disassembly was not fixed-width native syntax");
  require(std::ranges::any_of(
              state.instructions,
              [](const debugger::InstructionRow &instruction) {
                static constexpr std::array<std::string_view, 12> mnemonics{
                    "lwz", "stw", "stwu", "addi", "li", "cmpwi",
                    "bl",  "blt", "b",    "mflr", "mtlr", "blr"};
                return std::ranges::find(mnemonics, instruction.mnemonic) !=
                       mnemonics.end();
              }),
          "PowerPC disassembly did not contain architecture-native mnemonics");
  require(std::ranges::any_of(
              state.instructions,
              [](const debugger::InstructionRow &instruction) {
                return instruction.bytes ==
                       std::vector<std::uint8_t>{0x80, 0x61, 0x00, 0x00};
              }),
          "PowerPC instruction bytes were not decoded in big-endian order");
  require(!state.memory.empty(), "PowerPC stop did not publish memory bytes");
  require(!state.memory_regions.empty(),
          "PowerPC stop did not publish memory regions");
  require(!state.threads.empty() &&
              std::ranges::any_of(state.threads,
                                  [](const debugger::ThreadInfo &thread) {
                                    return thread.selected;
                                  }),
          "PowerPC stop did not publish a selected thread");
  static_cast<void>(local_module(state, executable));
  const debugger::ModuleInfo &module = local_module(state, executable);
  require(std::ranges::any_of(
              state.memory_regions,
              [&state, &module](const debugger::MemoryRegionInfo &region) {
                return region.name == module.path && region.readable &&
                       region.executable && !region.writable &&
                       state.pc >= region.start && state.pc < region.end;
              }),
          "PowerPC PC was not covered by the local ELF RX region");
  require(std::ranges::any_of(
              state.memory_regions,
              [&module](const debugger::MemoryRegionInfo &region) {
                return region.name == module.path && region.readable &&
                       region.writable && !region.executable;
              }),
          "PowerPC local ELF did not publish an RW non-executable region");
}

enum class ChallengeFunction : std::size_t {
  Entry,
  Verify,
  Mix,
  Checkpoint,
  Success,
  Failure,
  Count,
};

constexpr std::size_t kChallengeFunctionCount =
    static_cast<std::size_t>(ChallengeFunction::Count);
constexpr std::size_t kMaximumCampaignInstructionSteps = 512;

constexpr std::array<std::string_view, kChallengeFunctionCount>
    kChallengeSymbols{
        "crackme_entry",      "crackme_verify", "crackme_mix",
        "crackme_checkpoint", "crackme_success", "crackme_failure",
    };

using ChallengePath = std::array<ChallengeFunction, 5>;

struct CampaignExpectation final {
  std::string_view name;
  const char *input{};
  ChallengePath path;
  int exit_status{};
};

constexpr CampaignExpectation kSuccessCampaign{
    .name = "valid CTF! campaign",
    .input = "CTF!",
    .path = {ChallengeFunction::Entry, ChallengeFunction::Verify,
             ChallengeFunction::Mix, ChallengeFunction::Checkpoint,
             ChallengeFunction::Success},
    .exit_status = 0,
};

constexpr CampaignExpectation kFailureCampaign{
    .name = "invalid NOPE campaign",
    .input = "NOPE",
    .path = {ChallengeFunction::Entry, ChallengeFunction::Verify,
             ChallengeFunction::Mix, ChallengeFunction::Checkpoint,
             ChallengeFunction::Failure},
    .exit_status = 17,
};

struct ChallengeBreakpoint final {
  ChallengeFunction function{};
  std::uint32_t id{};
  std::vector<std::uint64_t> addresses;
};

using ChallengeBreakpoints =
    std::array<ChallengeBreakpoint, kChallengeFunctionCount>;

struct InstructionBudget final {
  std::size_t used{};
};

constexpr std::size_t challenge_index(ChallengeFunction function) {
  return static_cast<std::size_t>(function);
}

constexpr std::string_view challenge_symbol(ChallengeFunction function) {
  return kChallengeSymbols[challenge_index(function)];
}

std::string hex_address(std::uint64_t address) {
  std::array<char, 19> text{};
  std::snprintf(text.data(), text.size(), "0x%llx",
                static_cast<unsigned long long>(address));
  return text.data();
}

const char *session_state_name(debugger::SessionState state) {
  switch (state) {
  case debugger::SessionState::Initializing:
    return "initializing";
  case debugger::SessionState::NoTarget:
    return "no-target";
  case debugger::SessionState::TargetLoaded:
    return "target-loaded";
  case debugger::SessionState::Launching:
    return "launching";
  case debugger::SessionState::Connecting:
    return "connecting";
  case debugger::SessionState::Running:
    return "running";
  case debugger::SessionState::Stopped:
    return "stopped";
  case debugger::SessionState::Exited:
    return "exited";
  case debugger::SessionState::Error:
    return "error";
  case debugger::SessionState::ShuttingDown:
    return "shutting-down";
  }
  return "unknown";
}

std::string snapshot_details(const debugger::SessionSnapshot &state) {
  return "state=" + std::string{session_state_name(state.state)} +
         ", generation=" + std::to_string(state.generation) +
         ", revision=" + std::to_string(state.revision) +
         ", stop_revision=" + std::to_string(state.stop_revision) +
         ", pc=" + hex_address(state.pc);
}

const ChallengeBreakpoint &
breakpoint_for(const ChallengeBreakpoints &breakpoints,
               ChallengeFunction function) {
  return breakpoints[challenge_index(function)];
}

const debugger::BreakpointInfo &
published_breakpoint(const debugger::SessionSnapshot &state,
                     const ChallengeBreakpoint &breakpoint) {
  const auto found = std::ranges::find_if(
      state.breakpoints, [&breakpoint](const debugger::BreakpointInfo &current) {
        return current.id == breakpoint.id;
      });
  require(found != state.breakpoints.end(),
          "snapshot lost breakpoint " +
              std::string{challenge_symbol(breakpoint.function)} +
              " (id " + std::to_string(breakpoint.id) + ")");
  return *found;
}

bool at_breakpoint(const debugger::SessionSnapshot &state,
                   const ChallengeBreakpoint &breakpoint) {
  return std::ranges::find(breakpoint.addresses, state.pc) !=
         breakpoint.addresses.end();
}

ChallengeBreakpoint set_resolved_breakpoint(debugger::LldbEngine &engine,
                                            ChallengeFunction function) {
  const std::string_view symbol = challenge_symbol(function);
  const debugger::SessionSnapshot before = engine.snapshot();
  require(before.state == debugger::SessionState::Stopped,
          "cannot set " + std::string{symbol} +
              " breakpoint while target is not stopped");

  complete(engine.set_breakpoint(std::string{symbol}), 10s,
           "set breakpoint " + std::string{symbol});
  const debugger::SessionSnapshot state = engine.snapshot();
  require(state.generation == before.generation,
          "setting " + std::string{symbol} +
              " breakpoint changed the session generation");
  require(state.revision > before.revision,
          "setting " + std::string{symbol} +
              " breakpoint did not publish a new snapshot revision");
  require(state.state == debugger::SessionState::Stopped,
          "setting " + std::string{symbol} +
              " breakpoint changed the stopped state");

  const auto resolved = std::ranges::find_if(
      state.breakpoints,
      [&before, symbol](const debugger::BreakpointInfo &candidate) {
        return candidate.description.find(symbol) != std::string::npos &&
               std::ranges::none_of(
                   before.breakpoints,
                   [&candidate](const debugger::BreakpointInfo &previous) {
                     return previous.id == candidate.id;
                   });
      });
  require(resolved != state.breakpoints.end() && resolved->enabled &&
              !resolved->addresses.empty(),
          "breakpoint did not resolve retained ELF symbol " +
              std::string{symbol});
  require(resolved->hit_count == 0,
          "new " + std::string{symbol} +
              " breakpoint already had a nonzero hit count");
  return ChallengeBreakpoint{.function = function,
                             .id = resolved->id,
                             .addresses = resolved->addresses};
}

ChallengeBreakpoints
set_challenge_breakpoints(debugger::LldbEngine &engine) {
  ChallengeBreakpoints breakpoints;
  for (std::size_t index = 0; index < breakpoints.size(); ++index) {
    const auto function = static_cast<ChallengeFunction>(index);
    breakpoints[index] = set_resolved_breakpoint(engine, function);
  }
  return breakpoints;
}

void require_breakpoint_hit_count(
    const debugger::SessionSnapshot &state,
    const ChallengeBreakpoint &breakpoint, std::uint32_t expected,
    std::string_view context) {
  const debugger::BreakpointInfo &published =
      published_breakpoint(state, breakpoint);
  if (published.hit_count != expected) {
    fail(std::string{context} + ": " +
         std::string{challenge_symbol(breakpoint.function)} +
         " breakpoint expected " + std::to_string(expected) + " hit(s), got " +
         std::to_string(published.hit_count));
  }
}

void require_path_hit_counts(const debugger::SessionSnapshot &state,
                             const ChallengeBreakpoints &breakpoints,
                             const CampaignExpectation &expectation,
                             std::size_t reached_count,
                             std::string_view context) {
  require(reached_count <= expectation.path.size(),
          "invalid reached-function count in PowerPC campaign");
  const auto reached_end = expectation.path.begin() + reached_count;
  for (std::size_t index = 0; index < breakpoints.size(); ++index) {
    const ChallengeFunction function = static_cast<ChallengeFunction>(index);
    const bool reached =
        std::ranges::find(expectation.path.begin(), reached_end, function) !=
        reached_end;
    require_breakpoint_hit_count(state, breakpoints[index], reached ? 1U : 0U,
                                 context);
  }
}

void require_prologue_stop(const debugger::SessionSnapshot &state,
                           const ChallengeBreakpoint &breakpoint,
                           std::string_view context) {
  require(state.state == debugger::SessionState::Stopped,
          std::string{context} + ": expected a stopped snapshot, got " +
              snapshot_details(state));
  require(at_breakpoint(state, breakpoint),
          std::string{context} + ": expected " +
              std::string{challenge_symbol(breakpoint.function)} +
              " prologue at one of its resolved breakpoint addresses, got " +
              hex_address(state.pc));
  require_breakpoint_hit_count(state, breakpoint, 1U, context);
  require(has_function(state, challenge_symbol(breakpoint.function)),
          std::string{context} + ": stopped prologue did not retain the " +
              std::string{challenge_symbol(breakpoint.function)} +
              " symbolic frame");
}

debugger::SessionSnapshot wait_for_command_progress(
    debugger::LldbEngine &engine, const debugger::SessionSnapshot &previous,
    bool allow_exit, std::string_view operation) {
  debugger::SessionSnapshot state = wait_for_state(
      engine, engine.snapshot(),
      [&previous](const debugger::SessionSnapshot &candidate) {
        return candidate.generation != previous.generation ||
               (candidate.revision > previous.revision &&
                ((candidate.state == debugger::SessionState::Stopped &&
                  candidate.stop_revision > previous.stop_revision) ||
                 candidate.state == debugger::SessionState::Exited ||
                 candidate.state == debugger::SessionState::Error));
      },
      20s);

  require(state.generation == previous.generation,
          std::string{operation} + " changed generation: before " +
              snapshot_details(previous) + ", after " + snapshot_details(state));
  require(state.revision > previous.revision,
          std::string{operation} +
              " did not publish a newer snapshot revision: before " +
              snapshot_details(previous) + ", after " + snapshot_details(state));
  require(state.state != debugger::SessionState::Error,
          std::string{operation} + " entered debugger error state: " +
              (state.error.empty() ? snapshot_details(state) : state.error));
  if (state.state == debugger::SessionState::Stopped) {
    require(state.stop_revision > previous.stop_revision,
            std::string{operation} +
                " did not publish a newer stopped snapshot: before " +
                snapshot_details(previous) + ", after " +
                snapshot_details(state));
    return state;
  }
  require(allow_exit && state.state == debugger::SessionState::Exited,
          std::string{operation} + " reached an unexpected non-stopped state: " +
              snapshot_details(state));
  return state;
}

debugger::SessionSnapshot step_once(debugger::LldbEngine &engine,
                                    debugger::SessionSnapshot state,
                                    InstructionBudget &budget,
                                    bool allow_exit,
                                    std::string_view transition) {
  require(state.state == debugger::SessionState::Stopped,
          std::string{transition} + " cannot step from " +
              snapshot_details(state));
  if (budget.used >= kMaximumCampaignInstructionSteps) {
    fail(std::string{transition} + " exhausted the strict " +
         std::to_string(kMaximumCampaignInstructionSteps) +
         "-instruction campaign bound at " + hex_address(state.pc));
  }

  const std::uint64_t previous_pc = state.pc;
  ++budget.used;
  const std::string operation =
      std::string{transition} + " instruction step " +
      std::to_string(budget.used);
  complete(engine.step_instruction(false), 10s, operation);
  state = wait_for_command_progress(engine, state, allow_exit, operation);

  if (state.state == debugger::SessionState::Stopped) {
    require(state.pc != previous_pc,
            operation + " published a new stop without advancing PC from " +
                hex_address(previous_pc));
    require(std::ranges::any_of(
                state.instructions,
                [&state](const debugger::InstructionRow &instruction) {
                  return instruction.address == state.pc;
                }),
            operation +
                " did not publish disassembly for the newly stopped PC " +
                hex_address(state.pc));
  }
  return state;
}

debugger::SessionSnapshot continue_to_first_prologue(
    debugger::LldbEngine &engine, debugger::SessionSnapshot state,
    const ChallengeBreakpoints &breakpoints,
    const CampaignExpectation &expectation) {
  require_path_hit_counts(state, breakpoints, expectation, 0,
                          expectation.name);
  const ChallengeBreakpoint &entry =
      breakpoint_for(breakpoints, expectation.path.front());
  const std::string operation =
      std::string{expectation.name} + " continue to " +
      std::string{challenge_symbol(entry.function)};
  complete(engine.continue_execution(), 10s, operation);
  state = wait_for_command_progress(engine, state, false, operation);
  require_prologue_stop(state, entry, operation);
  require_path_hit_counts(state, breakpoints, expectation, 1, operation);
  return state;
}

debugger::SessionSnapshot step_to_next_prologue(
    debugger::LldbEngine &engine, debugger::SessionSnapshot state,
    const ChallengeBreakpoints &breakpoints,
    const CampaignExpectation &expectation, std::size_t next_index,
    InstructionBudget &budget) {
  require(next_index > 0 && next_index < expectation.path.size(),
          "invalid PowerPC challenge transition index");
  const ChallengeBreakpoint &source =
      breakpoint_for(breakpoints, expectation.path[next_index - 1]);
  const ChallengeBreakpoint &target =
      breakpoint_for(breakpoints, expectation.path[next_index]);
  const std::string transition =
      std::string{expectation.name} + " " +
      std::string{challenge_symbol(source.function)} + " -> " +
      std::string{challenge_symbol(target.function)};
  require_prologue_stop(state, source, transition);
  require_path_hit_counts(state, breakpoints, expectation, next_index,
                          transition);
  const std::size_t first_step = budget.used;

  while (budget.used < kMaximumCampaignInstructionSteps) {
    state = step_once(engine, std::move(state), budget, false, transition);
    if (at_breakpoint(state, target)) {
      require_prologue_stop(state, target, transition);
      require_path_hit_counts(state, breakpoints, expectation, next_index + 1,
                              transition);
      return state;
    }
    require_path_hit_counts(state, breakpoints, expectation, next_index,
                            transition);
  }

  fail(transition + " did not reach the expected prologue after " +
       std::to_string(budget.used - first_step) +
       " instruction steps; campaign bound=" +
       std::to_string(kMaximumCampaignInstructionSteps) +
       ", last " + snapshot_details(state));
}

debugger::SessionSnapshot step_final_body_to_exit(
    debugger::LldbEngine &engine, debugger::SessionSnapshot state,
    const ChallengeBreakpoints &breakpoints,
    const CampaignExpectation &expectation, InstructionBudget &budget) {
  const ChallengeBreakpoint &final_breakpoint =
      breakpoint_for(breakpoints, expectation.path.back());
  const std::string traversal =
      std::string{expectation.name} + " step " +
      std::string{challenge_symbol(final_breakpoint.function)} +
      " body to exact exit";
  require_prologue_stop(state, final_breakpoint, traversal);
  require_path_hit_counts(state, breakpoints, expectation,
                          expectation.path.size(), traversal);
  const std::size_t first_step = budget.used;

  while (budget.used < kMaximumCampaignInstructionSteps) {
    state = step_once(engine, std::move(state), budget, true, traversal);
    require_path_hit_counts(state, breakpoints, expectation,
                            expectation.path.size(), traversal);
    if (state.state == debugger::SessionState::Exited) {
      require(state.exit_status == expectation.exit_status,
              traversal + " reported status " +
                  std::to_string(state.exit_status) + ", expected " +
                  std::to_string(expectation.exit_status));
      return state;
    }
  }

  fail(traversal + " did not exit after " +
       std::to_string(budget.used - first_step) +
       " final-body/wrapper instruction steps; campaign bound=" +
       std::to_string(kMaximumCampaignInstructionSteps) +
       ", last " + snapshot_details(state));
}

std::shared_ptr<const debugger::DecompilerSnapshot>
wait_for_decompiler(debugger::DecompilerEngine &decompiler) {
  const auto deadline = std::chrono::steady_clock::now() + 30s;
  while (std::chrono::steady_clock::now() < deadline) {
    auto snapshot = decompiler.snapshot();
    if (!snapshot->loading &&
        (!snapshot->lines.empty() || !snapshot->error.empty())) {
      return snapshot;
    }
    std::this_thread::sleep_for(10ms);
  }
  return {};
}

void require_checkpoint_decompilation(const char *executable,
                                      const debugger::SessionSnapshot &state) {
  require(state.has_pc_file_address,
          "checkpoint PC did not map to a local ELF file address");
  const debugger::ModuleInfo &module = local_module(state, executable);
  const std::string module_id = module.uuid.empty() ? module.path : module.uuid;
  require(!module_id.empty(), "PowerPC module identity was empty");

  debugger::DecompilerEngine decompiler;
  decompiler.request(debugger::DecompilerRequest{
      .executable_path = executable,
      .module_id = module_id,
      .file_address = state.pc_file_address,
      .load_address = state.pc,
      .generation = state.generation,
      .debug_info_path = module.debug_info_path,
  });
  const auto decompiled = wait_for_decompiler(decompiler);
  require(decompiled != nullptr, "PowerPC decompilation timed out");
  require(decompiled->error.empty(),
          "PowerPC decompilation failed: " + decompiled->error);
  require(!decompiled->lines.empty(),
          "PowerPC decompiler returned no source lines");
  require(decompiled->requested_file_address == state.pc_file_address &&
              decompiled->requested_load_address == state.pc &&
              decompiled->generation == state.generation &&
              decompiled->module_id == module_id,
          "PowerPC decompiler lost file/load/module session mapping");
  require(std::ranges::any_of(
              decompiled->lines,
              [](const debugger::DecompiledLine &line) {
                return line.text.find("crackme_checkpoint") != std::string::npos;
              }),
          "PowerPC decompiler did not select crackme_checkpoint");
}

debugger::SessionSnapshot connect(debugger::LldbEngine &engine,
                                  QemuUserStub &stub) {
  wait_for_state(engine, engine.snapshot(), [](const auto &state) {
    return state.state == debugger::SessionState::NoTarget;
  });
  return debugger::test::connect_qemu_user(engine, stub, 20s,
                                           "connect qemu-ppc GDB stub");
}

void exercise_campaign(const char *executable, const char *qemu,
                       const CampaignExpectation &expectation,
                       bool inspect_success_checkpoint) {
  QemuUserStub stub{qemu, executable, expectation.input};
  debugger::LldbEngine engine;
  debugger::SessionSnapshot state = connect(engine, stub);
  require_powerpc_snapshot(state, executable);

  const ChallengeBreakpoints breakpoints = set_challenge_breakpoints(engine);
  state = engine.snapshot();
  InstructionBudget budget;
  state = continue_to_first_prologue(engine, std::move(state), breakpoints,
                                     expectation);

  for (std::size_t next_index = 1; next_index < expectation.path.size();
       ++next_index) {
    state = step_to_next_prologue(engine, std::move(state), breakpoints,
                                  expectation, next_index, budget);
    if (expectation.path[next_index] != ChallengeFunction::Checkpoint) {
      continue;
    }

    require(has_function(state, "crackme_checkpoint") &&
                has_function(state, "crackme_mix") &&
                has_function(state, "crackme_verify") &&
                has_function(state, "crackme_entry"),
            std::string{expectation.name} +
                " checkpoint stop did not expose "
                "checkpoint/mix/verify/entry nesting");
    require(!state.stack.empty(),
            std::string{expectation.name} +
                " checkpoint stop did not expose PowerPC stack activity");

    if (!inspect_success_checkpoint) {
      continue;
    }

    const debugger::CommandResult state_address =
        complete(engine.evaluate("&crackme_state"), 10s,
                 "resolve crackme_state address");
    require(state_address.has_numeric_value && state_address.numeric_value != 0,
            "crackme_state did not resolve to writable target memory");
    debugger::CommandResult bytes =
        complete(engine.read_memory(state_address.numeric_value, 16), 10s,
                 "read crackme_state");
    require(bytes.bytes.size() == 16 && bytes.bytes[0] == 0x43 &&
                bytes.bytes[1] == 0x54 && bytes.bytes[2] == 0x46 &&
                bytes.bytes[3] == 0x21,
            "crackme_state did not expose big-endian 0x43544621 bytes");
    complete(engine.write_memory(state_address.numeric_value + 12,
                                 {0xde, 0xad, 0xbe, 0xef}),
             10s, "write crackme_state");
    bytes =
        complete(engine.read_memory(state_address.numeric_value + 12, 4), 10s,
                 "read back crackme_state");
    require(bytes.bytes ==
                std::vector<std::uint8_t>{0xde, 0xad, 0xbe, 0xef},
            "PowerPC writable-state round trip changed byte order or value");
    require_checkpoint_decompilation(executable, state);
  }

  state = step_final_body_to_exit(engine, std::move(state), breakpoints,
                                  expectation, budget);
  require(state.state == debugger::SessionState::Exited &&
              state.exit_status == expectation.exit_status,
          std::string{expectation.name} +
              " did not exit with its exact expected status");
}

void exercise_success(const char *executable, const char *qemu) {
  exercise_campaign(executable, qemu, kSuccessCampaign, true);
}

void exercise_failure(const char *executable, const char *qemu) {
  exercise_campaign(executable, qemu, kFailureCampaign, false);
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s POWERPC32_ELF QEMU_PPC\n", argv[0]);
    return 2;
  }

  try {
    exercise_success(argv[1], argv[2]);
    exercise_failure(argv[1], argv[2]);
  } catch (const std::exception &error) {
    std::fprintf(stderr, "PowerPC32 QEMU robustness failure: %s\n",
                 error.what());
    return 1;
  }
  return 0;
}
