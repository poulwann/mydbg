#include "backend/decompiler/DecompilerEngine.h"
#include "EngineTestSupport.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
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

using namespace std::chrono_literals;

namespace {

using debugger::test::fail;
using debugger::test::require;

debugger::CommandResult complete(debugger::CommandTicket ticket,
                                 std::chrono::milliseconds timeout,
                                 std::string_view operation) {
  require(ticket.valid(), std::string{operation} + " returned no ticket");
  require(ticket.wait_for(timeout),
          std::string{operation} + " did not complete");
  debugger::CommandResult result = ticket.get();
  require(result.success,
          std::string{operation} + " failed: " + result.message);
  return result;
}

template <typename Predicate>
debugger::SessionSnapshot wait_for_snapshot(debugger::LldbEngine &engine,
                                            Predicate &&predicate,
                                            std::string_view operation) {
  return debugger::test::wait_for_state(
      engine, engine.snapshot(), predicate, 20s,
      std::string{"timed out waiting for "} + std::string{operation},
      std::string{"timed out waiting for an engine update during "} +
          std::string{operation});
}

debugger::SessionSnapshot launch_to_main(debugger::LldbEngine &engine,
                                         const char *executable,
                                         std::string seed) {
  complete(engine.launch({
               .executable = executable,
               .arguments = {std::move(seed)},
               .environment = {},
               .working_directory = {},
               .stop_policy = debugger::LaunchStopPolicy::Main,
           }),
           20s, "launch");
  debugger::SessionSnapshot stopped = wait_for_snapshot(
      engine,
      [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped ||
               snapshot.state == debugger::SessionState::Error ||
               snapshot.state == debugger::SessionState::Exited;
      },
      "initial main stop");
  require(stopped.state == debugger::SessionState::Stopped,
          stopped.error.empty() ? "native crackme did not stop at main"
                                : stopped.error);
  return stopped;
}

const debugger::BreakpointInfo &find_breakpoint(
    const debugger::SessionSnapshot &snapshot, std::uint32_t id) {
  const auto found = std::find_if(
      snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
      [id](const debugger::BreakpointInfo &breakpoint) {
        return breakpoint.id == id;
      });
  require(found != snapshot.breakpoints.end(), "breakpoint disappeared");
  return *found;
}

std::uint32_t set_resolved_breakpoint(debugger::LldbEngine &engine,
                                      std::string_view symbol) {
  const debugger::SessionSnapshot before = engine.snapshot();
  complete(engine.set_breakpoint(std::string{symbol}), 5s,
           std::string{"setting breakpoint on "} + std::string{symbol});
  const debugger::SessionSnapshot after = engine.snapshot();
  const auto added = std::find_if(
      after.breakpoints.begin(), after.breakpoints.end(),
      [&before](const debugger::BreakpointInfo &candidate) {
        return std::none_of(
            before.breakpoints.begin(), before.breakpoints.end(),
            [&candidate](const debugger::BreakpointInfo &existing) {
              return existing.id == candidate.id;
            });
      });
  require(added != after.breakpoints.end(),
          std::string{"no breakpoint was created for "} +
              std::string{symbol});
  require(!added->addresses.empty(),
          std::string{"breakpoint remained unresolved for "} +
              std::string{symbol});
  require(added->description.find(symbol) != std::string::npos,
          std::string{"breakpoint did not retain symbol identity for "} +
              std::string{symbol});
  return added->id;
}

void set_breakpoint_enabled(debugger::LldbEngine &engine, std::uint32_t id,
                            bool enabled) {
  complete(engine.set_breakpoint_enabled(id, enabled), 5s,
           enabled ? "enabling breakpoint" : "disabling breakpoint");
  const debugger::SessionSnapshot snapshot = engine.snapshot();
  const debugger::BreakpointInfo &breakpoint = find_breakpoint(snapshot, id);
  require(breakpoint.enabled == enabled,
          "breakpoint enabled state did not change");
}

const debugger::RegisterValue &find_register(
    const debugger::SessionSnapshot &snapshot, std::string_view name) {
  const auto *found = debugger::test::find_register(snapshot, name);
  require(found != nullptr,
          std::string{"missing native register "} + std::string{name});
  return *found;
}

bool frame_contains(const debugger::StackFrameInfo &frame,
                    std::string_view symbol) {
  return frame.function.find(symbol) != std::string::npos;
}

struct ChallengeBreakpoint {
  std::string symbol;
  std::uint32_t id{};
  std::vector<std::uint64_t> addresses;
};

struct ChallengeStepProgress {
  std::size_t instruction_count{};
  std::size_t external_call_step_overs{};
};

constexpr std::size_t kMaximumChallengeInstructions = 512U;
constexpr std::array<std::string_view, 5> kSuccessChallengePath{
    "crackme_entry", "crackme_verify", "crackme_mix", "crackme_checkpoint",
    "crackme_success"};
constexpr std::array<std::string_view, 5> kFailureChallengePath{
    "crackme_entry", "crackme_verify", "crackme_mix", "crackme_checkpoint",
    "crackme_failure"};

std::string format_address(std::uint64_t address) {
  std::array<char, 19> buffer{};
  std::snprintf(buffer.data(), buffer.size(), "0x%016llx",
                static_cast<unsigned long long>(address));
  return buffer.data();
}

ChallengeBreakpoint set_challenge_breakpoint(debugger::LldbEngine &engine,
                                             std::string_view symbol) {
  const std::uint32_t id = set_resolved_breakpoint(engine, symbol);
  const debugger::SessionSnapshot snapshot = engine.snapshot();
  const debugger::BreakpointInfo &published = find_breakpoint(snapshot, id);
  require(published.enabled,
          std::string{"new challenge breakpoint was disabled for "} +
              std::string{symbol});
  require(published.hit_count == 0U,
          std::string{"new challenge breakpoint had a nonzero hit count for "} +
              std::string{symbol});
  return ChallengeBreakpoint{
      .symbol = std::string{symbol},
      .id = id,
      .addresses = published.addresses,
  };
}

std::vector<ChallengeBreakpoint>
set_challenge_breakpoints(debugger::LldbEngine &engine) {
  constexpr std::array<std::string_view, 6> symbols{
      "crackme_entry",   "crackme_verify",  "crackme_mix",
      "crackme_checkpoint", "crackme_success", "crackme_failure"};
  std::vector<ChallengeBreakpoint> breakpoints;
  breakpoints.reserve(symbols.size());
  for (const std::string_view symbol : symbols) {
    breakpoints.push_back(set_challenge_breakpoint(engine, symbol));
  }
  return breakpoints;
}

const ChallengeBreakpoint &find_challenge_breakpoint(
    const std::vector<ChallengeBreakpoint> &breakpoints,
    std::string_view symbol) {
  const auto found = std::find_if(
      breakpoints.begin(), breakpoints.end(),
      [symbol](const ChallengeBreakpoint &breakpoint) {
        return breakpoint.symbol == symbol;
      });
  require(found != breakpoints.end(),
          std::string{"missing retained breakpoint for "} + std::string{symbol});
  return *found;
}

const ChallengeBreakpoint *challenge_breakpoint_at_pc(
    const std::vector<ChallengeBreakpoint> &breakpoints, std::uint64_t pc) {
  const auto found = std::find_if(
      breakpoints.begin(), breakpoints.end(),
      [pc](const ChallengeBreakpoint &breakpoint) {
        return std::find(breakpoint.addresses.begin(),
                         breakpoint.addresses.end(),
                         pc) != breakpoint.addresses.end();
      });
  return found == breakpoints.end() ? nullptr : &*found;
}


void require_breakpoint_stop(const debugger::SessionSnapshot &snapshot,
                             const ChallengeBreakpoint &expected) {
  require(snapshot.state == debugger::SessionState::Stopped,
          std::string{"target was not stopped at "} + expected.symbol);
  const debugger::BreakpointInfo &published =
      find_breakpoint(snapshot, expected.id);
  require(published.enabled,
          std::string{"breakpoint "} + std::to_string(expected.id) + " for " +
              expected.symbol + " was disabled when reached");
  require(std::find(expected.addresses.begin(), expected.addresses.end(),
                    snapshot.pc) != expected.addresses.end(),
          std::string{"stopped at "} + format_address(snapshot.pc) +
              " instead of the retained " + expected.symbol +
              " prologue address " + format_address(expected.addresses.front()));
  require(std::find(published.addresses.begin(), published.addresses.end(),
                    snapshot.pc) != published.addresses.end(),
          std::string{"breakpoint ID "} + std::to_string(expected.id) +
              " no longer published the caught prologue address for " +
              expected.symbol);
  require(published.hit_count == 1U,
          std::string{"breakpoint ID "} + std::to_string(expected.id) +
              " for " + expected.symbol + " reported hit count " +
              std::to_string(published.hit_count) + " instead of 1");
  require(debugger::test::has_function(snapshot, expected.symbol),
          std::string{"breakpoint ID "} + std::to_string(expected.id) +
              " stopped at the " + expected.symbol +
              " address without a matching stack frame");
}

debugger::SessionSnapshot wait_for_new_stopped_snapshot(
    debugger::LldbEngine &engine,
    const debugger::SessionSnapshot &before,
    std::string_view operation) {
  const std::uint64_t generation = before.generation;
  const std::uint64_t revision = before.revision;
  const std::uint64_t stop_revision = before.stop_revision;
  debugger::SessionSnapshot after = wait_for_snapshot(
      engine,
      [generation, revision,
       stop_revision](const debugger::SessionSnapshot &candidate) {
        return candidate.generation != generation ||
               candidate.state == debugger::SessionState::Error ||
               candidate.state == debugger::SessionState::Exited ||
               (candidate.state == debugger::SessionState::Stopped &&
                candidate.revision > revision &&
                candidate.stop_revision > stop_revision);
      },
      operation);
  require(after.generation == generation,
          std::string{operation} + " changed process generation from " +
              std::to_string(generation) + " to " +
              std::to_string(after.generation));
  require(after.revision > revision,
          std::string{operation} + " did not publish a newer snapshot revision");
  if (after.state != debugger::SessionState::Stopped) {
    fail(std::string{operation} + " reached terminal state " +
         std::to_string(static_cast<int>(after.state)) +
         (after.error.empty() ? std::string{} : ": " + after.error));
  }
  require(after.stop_revision > stop_revision,
          std::string{operation} + " did not publish a new stopped snapshot");
  return after;
}

debugger::SessionSnapshot continue_to_entry(
    debugger::LldbEngine &engine, const debugger::SessionSnapshot &before,
    const ChallengeBreakpoint &entry) {
  require(before.state == debugger::SessionState::Stopped,
          "entry campaign did not start from a stopped main");
  complete(engine.continue_execution(), 5s,
           "continuing from main to crackme_entry");
  debugger::SessionSnapshot entry_stop = wait_for_new_stopped_snapshot(
      engine, before, "crackme_entry breakpoint");
  require_breakpoint_stop(entry_stop, entry);
  return entry_stop;
}

const debugger::InstructionRow &
instruction_at_pc(const debugger::SessionSnapshot &snapshot) {
  const auto found = std::find_if(
      snapshot.instructions.begin(), snapshot.instructions.end(),
      [&snapshot](const debugger::InstructionRow &instruction) {
        return instruction.address == snapshot.pc;
      });
  require(found != snapshot.instructions.end(),
          std::string{"stopped snapshot had no instruction at PC "} +
              format_address(snapshot.pc));
  require(!found->bytes.empty(),
          std::string{"instruction at PC "} + format_address(snapshot.pc) +
              " had no opcode bytes");
  return *found;
}

std::optional<std::uint64_t>
direct_x86_call_target(const debugger::InstructionRow &instruction) {
  std::size_t opcode_index = 0;
  while (opcode_index < instruction.bytes.size()) {
    const std::uint8_t byte = instruction.bytes[opcode_index];
    if (byte == UINT8_C(0x66) || byte == UINT8_C(0x67) ||
        byte == UINT8_C(0xf2) || byte == UINT8_C(0xf3) ||
        byte == UINT8_C(0x2e) || byte == UINT8_C(0x36) ||
        byte == UINT8_C(0x3e) || byte == UINT8_C(0x26) ||
        byte == UINT8_C(0x64) || byte == UINT8_C(0x65) ||
        (byte >= UINT8_C(0x40) && byte <= UINT8_C(0x4f))) {
      ++opcode_index;
      continue;
    }
    break;
  }
  if (opcode_index >= instruction.bytes.size() ||
      instruction.bytes[opcode_index] != UINT8_C(0xe8) ||
      instruction.bytes.size() < opcode_index + 5U) {
    return std::nullopt;
  }

  const std::uint32_t encoded =
      static_cast<std::uint32_t>(instruction.bytes[opcode_index + 1U]) |
      (static_cast<std::uint32_t>(instruction.bytes[opcode_index + 2U])
       << 8U) |
      (static_cast<std::uint32_t>(instruction.bytes[opcode_index + 3U])
       << 16U) |
      (static_cast<std::uint32_t>(instruction.bytes[opcode_index + 4U])
       << 24U);
  const std::int64_t displacement =
      static_cast<std::int64_t>(static_cast<std::int32_t>(encoded));
  const std::uint64_t next_instruction =
      instruction.address + instruction.bytes.size();
  if (displacement >= 0) {
    return next_instruction + static_cast<std::uint64_t>(displacement);
  }
  return next_instruction - static_cast<std::uint64_t>(-displacement);
}

std::optional<std::uint64_t>
resolved_call_target(const debugger::InstructionRow &instruction) {
  if (const std::optional<std::uint64_t> direct =
          direct_x86_call_target(instruction)) {
    require(instruction.flow_target == direct,
            "captured call destination disagreed with its relative encoding");
  }
  return instruction.flow_target;
}

bool is_challenge_prologue(
    const std::vector<ChallengeBreakpoint> &breakpoints,
    std::uint64_t address) {
  return challenge_breakpoint_at_pc(breakpoints, address) != nullptr;
}

debugger::SessionSnapshot step_one_challenge_instruction(
    debugger::LldbEngine &engine, const debugger::SessionSnapshot &before,
    const std::vector<ChallengeBreakpoint> &breakpoints,
    ChallengeStepProgress &progress, std::string_view destination) {
  require(before.state == debugger::SessionState::Stopped,
          std::string{"cannot instruction-step toward "} +
              std::string{destination} + " from a non-stopped state");
  require(progress.instruction_count < kMaximumChallengeInstructions,
          std::string{"exceeded the "} +
              std::to_string(kMaximumChallengeInstructions) +
              "-instruction challenge bound while stepping toward " +
              std::string{destination} + " from " +
              format_address(before.pc));

  const debugger::InstructionRow &instruction = instruction_at_pc(before);
  bool step_over = false;
  std::optional<std::uint64_t> call_target;
  if (instruction.flow_kind == debugger::InstructionFlowKind::Call) {
    call_target = resolved_call_target(instruction);
    require(call_target.has_value() && *call_target != 0,
            std::string{"could not resolve x86-64 call target at "} +
                format_address(before.pc) + " while stepping toward " +
                std::string{destination});
    step_over = !is_challenge_prologue(breakpoints, *call_target);
  }

  const std::size_t ordinal = progress.instruction_count + 1U;
  std::string operation =
      "instruction-step #" + std::to_string(ordinal) + " at " +
      format_address(before.pc) + " toward " + std::string{destination};
  if (step_over) {
    operation += " (over external call to " + format_address(*call_target) + ")";
  }
  complete(engine.step_instruction(step_over), 5s, operation);
  debugger::SessionSnapshot after =
      wait_for_new_stopped_snapshot(engine, before, operation);
  require(after.pc != before.pc,
          operation + " republished the same PC instead of advancing");
  require(std::any_of(
              after.instructions.begin(), after.instructions.end(),
              [&after](const debugger::InstructionRow &candidate) {
                return candidate.address == after.pc;
              }),
          operation + " did not refresh disassembly at the new PC " +
              format_address(after.pc));

  progress.instruction_count = ordinal;
  if (step_over) {
    ++progress.external_call_step_overs;
  }
  return after;
}

debugger::SessionSnapshot step_to_challenge_breakpoint(
    debugger::LldbEngine &engine, debugger::SessionSnapshot state,
    const ChallengeBreakpoint &expected,
    const std::vector<ChallengeBreakpoint> &breakpoints,
    ChallengeStepProgress &progress) {
  require(state.state == debugger::SessionState::Stopped,
          std::string{"cannot begin stepping toward "} + expected.symbol +
              " from a non-stopped state");
  require(std::find(expected.addresses.begin(), expected.addresses.end(),
                    state.pc) == expected.addresses.end(),
          std::string{"stepping campaign was already at "} + expected.symbol);
  const std::size_t first_step = progress.instruction_count;

  while (true) {
    state = step_one_challenge_instruction(engine, state, breakpoints, progress,
                                           expected.symbol);
    const ChallengeBreakpoint *caught =
        challenge_breakpoint_at_pc(breakpoints, state.pc);
    if (caught == nullptr) {
      continue;
    }
    require(caught->id == expected.id,
            std::string{"caught unexpected challenge prologue "} +
                caught->symbol + " (breakpoint ID " +
                std::to_string(caught->id) + ") at " +
                format_address(state.pc) + " while stepping toward " +
                expected.symbol + " (breakpoint ID " +
                std::to_string(expected.id) + ")");
    require(progress.instruction_count > first_step,
            std::string{"no instruction was stepped before reaching "} +
                expected.symbol);
    require_breakpoint_stop(state, expected);
    return state;
  }
}

debugger::SessionSnapshot step_until_challenge_returns(
    debugger::LldbEngine &engine, debugger::SessionSnapshot state,
    const ChallengeBreakpoint &final_breakpoint,
    const ChallengeBreakpoint &entry,
    const std::vector<ChallengeBreakpoint> &breakpoints,
    ChallengeStepProgress &progress) {
  require_breakpoint_stop(state, final_breakpoint);
  require(debugger::test::has_function(state, entry.symbol),
          std::string{"final "} + final_breakpoint.symbol +
              " stop did not retain its crackme_entry caller");
  const std::size_t first_step = progress.instruction_count;
  const std::size_t prior_external_steps =
      progress.external_call_step_overs;

  while (debugger::test::has_function(state, entry.symbol)) {
    state = step_one_challenge_instruction(
        engine, state, breakpoints, progress,
        std::string{"returning from "} + final_breakpoint.symbol);
    if (const ChallengeBreakpoint *caught =
            challenge_breakpoint_at_pc(breakpoints, state.pc)) {
      fail(std::string{"unexpected repeated challenge prologue "} +
           caught->symbol + " (breakpoint ID " +
           std::to_string(caught->id) +
           ") while instruction-stepping the final challenge body");
    }
  }

  require(progress.instruction_count > first_step,
          std::string{"no final challenge instructions were stepped after "} +
              final_breakpoint.symbol);
  require(progress.external_call_step_overs > prior_external_steps,
          std::string{"no external libc call was instruction-stepped over in "} +
              final_breakpoint.symbol);
  require(state.state == debugger::SessionState::Stopped,
          "challenge return did not leave a stopped snapshot in main");
  require(!debugger::test::has_function(state, entry.symbol),
          "crackme_entry remained on the stack after its return was stepped");
  return state;
}

template <std::size_t PathSize>
void require_challenge_hit_counts(
    const debugger::SessionSnapshot &snapshot,
    const std::vector<ChallengeBreakpoint> &breakpoints,
    const std::array<std::string_view, PathSize> &expected_path) {
  for (const ChallengeBreakpoint &breakpoint : breakpoints) {
    const bool expected =
        std::find(expected_path.begin(), expected_path.end(),
                  breakpoint.symbol) != expected_path.end();
    const debugger::BreakpointInfo &published =
        find_breakpoint(snapshot, breakpoint.id);
    const std::uint32_t expected_hits = expected ? 1U : 0U;
    require(published.hit_count == expected_hits,
            std::string{"breakpoint ID "} + std::to_string(breakpoint.id) +
                " for " + breakpoint.symbol + " reported hit count " +
                std::to_string(published.hit_count) + " instead of " +
                std::to_string(expected_hits));
  }
}

debugger::SessionSnapshot continue_to_expected_exit(
    debugger::LldbEngine &engine, const debugger::SessionSnapshot &before,
    int expected_status, std::string_view description) {
  require(before.state == debugger::SessionState::Stopped,
          std::string{description} + " exit continue did not start stopped");
  const std::uint64_t generation = before.generation;
  const std::uint64_t revision = before.revision;
  complete(engine.continue_execution(), 5s,
           std::string{"continuing "} + std::string{description} + " to exit");
  debugger::SessionSnapshot exited = wait_for_snapshot(
      engine,
      [generation](const debugger::SessionSnapshot &snapshot) {
        return snapshot.generation != generation ||
               snapshot.state == debugger::SessionState::Exited ||
               snapshot.state == debugger::SessionState::Error;
      },
      std::string{description} + " process exit");
  require(exited.generation == generation,
          std::string{description} +
              " exit changed the process generation unexpectedly");
  require(exited.revision > revision,
          std::string{description} +
              " exit did not publish a newer snapshot revision");
  require(exited.state == debugger::SessionState::Exited,
          exited.error.empty()
              ? std::string{description} + " entered a non-exited terminal state"
              : exited.error);
  require(exited.exit_status == expected_status,
          std::string{description} + " reported exit status " +
              std::to_string(exited.exit_status) + " instead of " +
              std::to_string(expected_status));
  return exited;
}

void require_nested_checkpoint_stack(
    const debugger::SessionSnapshot &snapshot) {
  const auto selected = std::find_if(
      snapshot.threads.begin(), snapshot.threads.end(),
      [&snapshot](const debugger::ThreadInfo &thread) {
        return thread.id == snapshot.thread_id;
      });
  require(selected != snapshot.threads.end(),
          "selected native thread was not captured");

  constexpr std::array<std::string_view, 5> expected{
      "crackme_checkpoint", "crackme_mix", "crackme_verify",
      "crackme_entry", "main"};
  std::size_t search_from = 0;
  for (const std::string_view symbol : expected) {
    const auto frame = std::find_if(
        selected->frames.begin() + static_cast<std::ptrdiff_t>(search_from),
        selected->frames.end(), [symbol](const debugger::StackFrameInfo &value) {
          return frame_contains(value, symbol);
        });
    require(frame != selected->frames.end(),
            std::string{"missing nested frame "} + std::string{symbol});
    search_from =
        static_cast<std::size_t>(frame - selected->frames.begin()) + 1U;
  }
}

const debugger::ModuleInfo &find_executable_module(
    const debugger::SessionSnapshot &snapshot, const char *executable) {
  const auto *found = debugger::test::local_module(snapshot, executable);
  require(found != nullptr,
          "local crackme ELF was absent from the module snapshot");
  return *found;
}

std::shared_ptr<const debugger::DecompilerSnapshot>
wait_for_decompiler(debugger::DecompilerEngine &decompiler,
                    const debugger::DecompilerRequest &request) {
  const auto deadline = std::chrono::steady_clock::now() + 30s;
  while (std::chrono::steady_clock::now() < deadline) {
    std::shared_ptr<const debugger::DecompilerSnapshot> snapshot =
        decompiler.snapshot();
    const bool matching =
        snapshot->executable_path == request.executable_path &&
        snapshot->module_id == request.module_id &&
        snapshot->requested_file_address == request.file_address &&
        snapshot->requested_load_address == request.load_address &&
        snapshot->generation == request.generation;
    if (matching && !snapshot->loading &&
        (!snapshot->lines.empty() || !snapshot->error.empty())) {
      return snapshot;
    }
    std::this_thread::sleep_for(10ms);
  }
  fail("timed out waiting for local ELF decompilation");
}

void require_local_decompilation(const debugger::SessionSnapshot &stopped,
                                 const char *executable) {
  require(stopped.has_pc_file_address,
          "checkpoint PC had no local ELF file address");
  const debugger::ModuleInfo &module =
      find_executable_module(stopped, executable);
  const std::string module_id = module.uuid.empty() ? module.path : module.uuid;
  require(!module_id.empty(), "local ELF module had no stable identity");

  debugger::DecompilerEngine decompiler;
  const debugger::DecompilerRequest request{
      .executable_path = executable,
      .module_id = module_id,
      .file_address = stopped.pc_file_address,
      .load_address = stopped.pc,
      .generation = stopped.generation,
      .debug_info_path = module.debug_info_path,
  };
  decompiler.request(request);
  const std::shared_ptr<const debugger::DecompilerSnapshot> result =
      wait_for_decompiler(decompiler, request);
  require(result->error.empty(),
          std::string{"local ELF decompilation failed: "} + result->error);
  require(!result->lines.empty(),
          "local ELF decompilation returned no source lines");
  require(result->function_file_address != 0,
          "decompiler returned no function file address");
  require(result->function_min_file_address <= stopped.pc_file_address &&
              stopped.pc_file_address <= result->function_max_file_address,
          "decompiler selected a function outside the stopped PC");
  require(std::any_of(result->lines.begin(), result->lines.end(),
                      [](const debugger::DecompiledLine &line) {
                        return line.text.find("crackme_checkpoint") !=
                               std::string::npos;
                      }),
          "decompiler did not identify crackme_checkpoint");
}

void require_native_snapshot(const debugger::SessionSnapshot &snapshot,
                             const char *executable) {
  require(snapshot.mode == debugger::SessionMode::Local,
          "native test did not use local session mode");
  require(snapshot.architecture.starts_with("x86_64"),
          std::string{"expected x86_64 snapshot, got "} +
              snapshot.architecture);
  require(snapshot.target_triple.find("x86_64") != std::string::npos,
          "target triple did not identify x86_64");
  require(snapshot.address_byte_size == 8U,
          "x86_64 snapshot did not report 64-bit addresses");
  require(snapshot.byte_order == "little",
          "x86_64 snapshot did not report little-endian byte order");
  require(snapshot.supports_intel_syntax,
          "x86_64 snapshot did not expose native syntax selection");
  require(snapshot.pc != 0 && snapshot.sp != 0,
          "native PC/SP were not captured");
  require(!snapshot.instructions.empty(),
          "native instructions were not captured");
  require(!snapshot.registers.empty(), "native registers were not captured");
  require(!snapshot.memory.empty(), "native stack memory was not captured");
  require(!snapshot.memory_regions.empty(),
          "native memory map was not captured");
  require(!snapshot.modules.empty(), "native modules were not captured");
  require(!snapshot.threads.empty(), "native threads were not captured");
  require(!snapshot.stack.empty(), "native stack words were not captured");
  static_cast<void>(find_executable_module(snapshot, executable));

  const debugger::RegisterValue &rip = find_register(snapshot, "rip");
  const debugger::RegisterValue &rsp = find_register(snapshot, "rsp");
  static_cast<void>(find_register(snapshot, "rbp"));
  static_cast<void>(find_register(snapshot, "rax"));
  require(rip.has_numeric_value && rip.numeric_value == snapshot.pc,
          "RIP did not match the captured program counter");
  require(rsp.has_numeric_value && rsp.numeric_value == snapshot.sp,
          "RSP did not match the captured stack pointer");
}

void require_native_syntaxes(debugger::LldbEngine &engine) {
  complete(engine.set_intel_syntax(false), 5s, "selecting AT&T syntax");
  debugger::SessionSnapshot snapshot = engine.snapshot();
  require(!snapshot.intel_syntax, "AT&T syntax selection was not retained");
  require(std::any_of(snapshot.instructions.begin(), snapshot.instructions.end(),
                      [](const debugger::InstructionRow &instruction) {
                        return instruction.operands.find('%') !=
                               std::string::npos;
                      }),
          "AT&T disassembly did not use percent-prefixed registers");

  complete(engine.set_intel_syntax(true), 5s, "selecting Intel syntax");
  snapshot = engine.snapshot();
  require(snapshot.intel_syntax, "Intel syntax selection was not retained");
  require(std::none_of(snapshot.instructions.begin(), snapshot.instructions.end(),
                       [](const debugger::InstructionRow &instruction) {
                         return instruction.operands.find('%') !=
                                std::string::npos;
                       }),
          "Intel disassembly retained AT&T register prefixes");
  require(std::any_of(snapshot.instructions.begin(), snapshot.instructions.end(),
                      [](const debugger::InstructionRow &instruction) {
                        return instruction.operands.find("rbp") !=
                                   std::string::npos ||
                               instruction.operands.find("rsp") !=
                                   std::string::npos ||
                               instruction.operands.find("rax") !=
                                   std::string::npos ||
                               instruction.operands.find("rdi") !=
                                   std::string::npos;
                      }),
          "Intel disassembly exposed no native x86-64 register operands");
}

void require_register_mutation(debugger::LldbEngine &engine) {
  debugger::CommandResult original =
      complete(engine.read_register("rax"), 5s, "reading RAX");
  require(original.has_numeric_value, "RAX was not numerically readable");
  const std::uint64_t changed_value = original.numeric_value ^ UINT64_C(1);

  debugger::CommandResult changed = complete(
      engine.write_register("rax", changed_value), 5s, "mutating RAX");
  require(changed.has_numeric_value && changed.numeric_value == changed_value,
          "RAX write did not report the mutated value");
  debugger::CommandResult observed =
      complete(engine.read_register("rax"), 5s, "reading mutated RAX");
  require(observed.has_numeric_value && observed.numeric_value == changed_value,
          "RAX mutation was not observable");

  complete(engine.write_register("rax", original.numeric_value), 5s,
           "restoring RAX");
  debugger::CommandResult restored =
      complete(engine.read_register("rax"), 5s, "reading restored RAX");
  require(restored.has_numeric_value &&
              restored.numeric_value == original.numeric_value,
          "RAX was not restored");
}

void require_memory_mutation(debugger::LldbEngine &engine) {
  debugger::CommandResult address = complete(
      engine.evaluate("&crackme_writable_state"), 5s,
      "resolving crackme_writable_state");
  require(address.has_numeric_value && address.numeric_value != 0,
          "writable state did not resolve to an address");

  debugger::CommandResult original =
      complete(engine.read_memory(address.numeric_value, sizeof(std::uint64_t)),
               5s, "reading writable state");
  require(original.bytes.size() == sizeof(std::uint64_t),
          "writable state read returned the wrong byte count");
  std::vector<std::uint8_t> changed = original.bytes;
  changed.front() ^= UINT8_C(0x5a);

  complete(engine.write_memory(address.numeric_value, changed), 5s,
           "mutating writable state");
  debugger::CommandResult observed =
      complete(engine.read_memory(address.numeric_value, changed.size()), 5s,
               "reading mutated writable state");
  require(observed.bytes == changed,
          "writable state mutation was not observable");
  const debugger::SessionSnapshot mutated_snapshot = engine.snapshot();
  require(std::any_of(mutated_snapshot.patches.begin(),
                      mutated_snapshot.patches.end(),
                      [address](const debugger::PatchInfo &patch) {
                        return patch.address <= address.numeric_value &&
                               address.numeric_value <
                                   patch.address + patch.replacement.size();
                      }),
          "memory mutation was not recorded as a patch");

  complete(engine.write_memory(address.numeric_value, original.bytes), 5s,
           "restoring writable state");
  debugger::CommandResult restored =
      complete(engine.read_memory(address.numeric_value, original.bytes.size()),
               5s, "reading restored writable state");
  require(restored.bytes == original.bytes,
          "writable state bytes were not restored");
  const debugger::SessionSnapshot restored_snapshot = engine.snapshot();
  require(std::none_of(restored_snapshot.patches.begin(),
                       restored_snapshot.patches.end(),
                       [address](const debugger::PatchInfo &patch) {
                         return patch.address <= address.numeric_value &&
                                address.numeric_value <
                                    patch.address + patch.replacement.size();
                       }),
          "restored writable state remained recorded as a patch");
}

void exercise_campaign(const char *executable, bool successful) {
  debugger::LldbEngine engine;
  wait_for_snapshot(engine,
                    [](const debugger::SessionSnapshot &snapshot) {
                      return snapshot.state == debugger::SessionState::NoTarget;
                    },
                    successful ? "engine initialization"
                               : "failure engine initialization");
  debugger::SessionSnapshot stopped =
      launch_to_main(engine, executable, successful ? "CTF!" : "wrong");
  if (successful) {
    require_native_snapshot(stopped, executable);
  }

  const std::vector<ChallengeBreakpoint> breakpoints =
      set_challenge_breakpoints(engine);
  const ChallengeBreakpoint &entry =
      find_challenge_breakpoint(breakpoints, "crackme_entry");
  const ChallengeBreakpoint &verify =
      find_challenge_breakpoint(breakpoints, "crackme_verify");
  const ChallengeBreakpoint &mix =
      find_challenge_breakpoint(breakpoints, "crackme_mix");
  const ChallengeBreakpoint &checkpoint =
      find_challenge_breakpoint(breakpoints, "crackme_checkpoint");
  const ChallengeBreakpoint &success =
      find_challenge_breakpoint(breakpoints, "crackme_success");
  const ChallengeBreakpoint &failure =
      find_challenge_breakpoint(breakpoints, "crackme_failure");
  const ChallengeBreakpoint &terminal = successful ? success : failure;
  const ChallengeBreakpoint &unreached = successful ? failure : success;

  set_breakpoint_enabled(engine, unreached.id, false);
  set_breakpoint_enabled(engine, unreached.id, true);
  stopped = engine.snapshot();
  stopped = continue_to_entry(engine, stopped, entry);

  ChallengeStepProgress progress;
  stopped =
      step_to_challenge_breakpoint(engine, std::move(stopped), verify,
                                   breakpoints, progress);
  stopped =
      step_to_challenge_breakpoint(engine, std::move(stopped), mix,
                                   breakpoints, progress);
  stopped =
      step_to_challenge_breakpoint(engine, std::move(stopped), checkpoint,
                                   breakpoints, progress);
  require_nested_checkpoint_stack(stopped);
  if (successful) {
    require_native_snapshot(stopped, executable);
    require_native_syntaxes(engine);
    require_register_mutation(engine);
    require_memory_mutation(engine);
    stopped = engine.snapshot();
    require_local_decompilation(stopped, executable);
  }

  stopped =
      step_to_challenge_breakpoint(engine, std::move(stopped), terminal,
                                   breakpoints, progress);
  if (successful) {
    require(!stopped.threads.empty() && !stopped.threads.front().frames.empty(),
            "success stop had no stack frame");
    require(debugger::test::has_function(stopped, "crackme_success"),
            "success breakpoint did not stop in crackme_success");
  }

  stopped = step_until_challenge_returns(
      engine, std::move(stopped), terminal, entry, breakpoints, progress);
  require_challenge_hit_counts(
      stopped, breakpoints,
      successful ? kSuccessChallengePath : kFailureChallengePath);
  const debugger::SessionSnapshot exited = continue_to_expected_exit(
      engine, stopped, successful ? 0 : 17,
      successful ? "successful crackme" : "failing crackme");
  require(exited.process_output.find(
              successful ? "crackme_success seed=0x43544621"
                         : "crackme_failure seed=0x00000000") != std::string::npos,
          successful ? "correct seed did not produce the success output"
                     : "incorrect seed did not produce the failure output");
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s X86_64_CRACKME\n", argv[0]);
    return 2;
  }

  try {
    exercise_campaign(argv[1], true);
    exercise_campaign(argv[1], false);
  } catch (const std::exception &error) {
    std::fprintf(stderr, "x86-64 crackme test failure: %s\n", error.what());
    return 1;
  }
  return 0;
}
