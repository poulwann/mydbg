#include "EngineTestSupport.h"
#include "RemoteProcessHarness.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>

#include <utility>
using namespace std::chrono_literals;

namespace {

using debugger::test::require;

template <typename Predicate>
debugger::SessionSnapshot wait_for_state(
    debugger::LldbEngine &engine, debugger::SessionSnapshot current,
    const Predicate &predicate, std::chrono::milliseconds timeout = 15s) {
  return debugger::test::wait_for_state(
      engine, std::move(current), predicate, timeout,
      "timed out waiting for remote engine state",
      "timed out waiting for remote engine update");
}

debugger::CommandResult complete(debugger::CommandTicket ticket,
                                 std::chrono::milliseconds timeout,
                                 std::string_view operation) {
  require(ticket.valid(), std::string{operation} + " returned no ticket");
  require(ticket.wait_for(timeout), std::string{operation} + " timed out");
  debugger::CommandResult result = ticket.get();
  require(result.success,
          std::string{operation} + " failed: " + result.message);
  return result;
}

const debugger::RegisterValue &find_register(
    const debugger::SessionSnapshot &state, std::string_view name) {
  const auto *found = debugger::test::find_register(state, name);
  require(found != nullptr,
          "remote snapshot omitted native register " + std::string{name});
  return *found;
}

void require_remote_x86_snapshot(const debugger::SessionSnapshot &state,
                                 const char *debuggee) {
  require(state.mode == debugger::SessionMode::Remote,
          "lldb-server transport was not identified as remote");
  require(state.architecture.starts_with("x86_64") ||
              state.architecture.starts_with("amd64"),
          "remote snapshot did not identify x86-64: " + state.architecture);
  require(state.target_triple.find("x86_64") != std::string::npos ||
              state.target_triple.find("amd64") != std::string::npos,
          "remote target triple did not identify x86-64");
  require(state.byte_order == "little",
          "remote x86-64 snapshot was not little-endian");
  require(state.address_byte_size == 8,
          "remote x86-64 snapshot did not use eight-byte addresses");
  require(state.supports_intel_syntax && state.intel_syntax,
          "remote x86-64 snapshot did not expose Intel syntax");
  require(state.pc != 0 && state.sp != 0,
          "remote x86-64 PC/SP were not captured");

  const debugger::RegisterValue &rip = find_register(state, "rip");
  const debugger::RegisterValue &rsp = find_register(state, "rsp");
  static_cast<void>(find_register(state, "rbp"));
  require(rip.has_numeric_value && rip.numeric_value == state.pc,
          "remote RIP did not match the stopped PC");
  require(rsp.has_numeric_value && rsp.numeric_value == state.sp,
          "remote RSP did not match the stopped stack pointer");

  require(!state.instructions.empty(),
          "remote x86-64 instructions were not captured");
  require(std::ranges::any_of(
              state.instructions,
              [&state](const debugger::InstructionRow &instruction) {
                return instruction.address == state.pc &&
                       !instruction.bytes.empty() &&
                       !instruction.mnemonic.empty();
              }),
          "remote disassembly omitted the stopped PC");
  require(std::ranges::none_of(
              state.instructions,
              [](const debugger::InstructionRow &instruction) {
                return instruction.operands.find('%') != std::string::npos;
              }),
          "remote Intel disassembly used AT&T register prefixes");
  require(std::ranges::any_of(
              state.instructions,
              [](const debugger::InstructionRow &instruction) {
                constexpr std::array<std::string_view, 5> registers{
                    "rax", "rbp", "rsp", "rdi", "rip"};
                return std::ranges::any_of(
                    registers, [&instruction](std::string_view name) {
                      return instruction.operands.find(name) !=
                             std::string::npos;
                    });
              }),
          "remote disassembly exposed no native x86-64 register spelling");
  require(!state.memory.empty() && !state.memory_regions.empty(),
          "remote stop did not publish memory and mappings");
  require(std::ranges::any_of(
              state.threads, [&state](const debugger::ThreadInfo &thread) {
                return thread.selected && thread.id == state.thread_id;
              }),
          "remote stop did not identify its selected thread");
  const std::filesystem::path requested{debuggee};
  require(std::ranges::any_of(
              state.modules,
              [&requested](const debugger::ModuleInfo &module) {
                return module.path == requested.string() ||
                       std::filesystem::path{module.path}.filename() ==
                           requested.filename();
              }),
          "remote stop did not retain the local x86-64 ELF module");
  require(state.has_pc_file_address && !state.pc_module_path.empty(),
          "remote PC did not map to the local ELF image");
}

void exercise_remote(const char *debuggee, const char *lldb_server) {
  debugger::test::LldbServerStub stub{lldb_server, debuggee, "CTF!"};
  debugger::LldbEngine engine;
  wait_for_state(engine, engine.snapshot(), [](const auto &state) {
    return state.state == debugger::SessionState::NoTarget;
  });

  complete(engine.connect_remote({.executable = debuggee,
                                  .endpoint = stub.endpoint(),
                                  .mode = debugger::SessionMode::Remote}),
           15s, "connect lldb-server transport");
  debugger::SessionSnapshot state = wait_for_state(
      engine, engine.snapshot(), [](const auto &candidate) {
        return candidate.state == debugger::SessionState::Stopped ||
               candidate.state == debugger::SessionState::Error;
      });
  require(state.state == debugger::SessionState::Stopped,
          state.error.empty() ? "remote process did not stop" : state.error);

  complete(engine.set_breakpoint("main"), 10s,
           "set remote main breakpoint");
  require(std::ranges::any_of(
              engine.snapshot().breakpoints,
              [](const debugger::BreakpointInfo &breakpoint) {
                return !breakpoint.addresses.empty() &&
                       breakpoint.description.find("main") !=
                           std::string::npos;
              }),
          "remote symbolic breakpoint did not resolve");

  const std::uint64_t initial_stop = state.stop_revision;
  complete(engine.continue_execution(), 10s, "continue remote target");
  state = wait_for_state(engine, engine.snapshot(), [initial_stop](const auto &next) {
    return next.state == debugger::SessionState::Error ||
           next.state == debugger::SessionState::Exited ||
           (next.state == debugger::SessionState::Stopped &&
            next.stop_revision > initial_stop);
  });
  require(state.state == debugger::SessionState::Stopped,
          "remote target did not stop at main");
  require_remote_x86_snapshot(state, debuggee);
  require(std::ranges::any_of(
              state.threads, [](const debugger::ThreadInfo &thread) {
                return std::ranges::any_of(
                    thread.frames, [](const debugger::StackFrameInfo &frame) {
                      return frame.function.find("main") !=
                             std::string::npos;
                    });
              }),
          "remote main breakpoint had no symbolic frame");

  const std::uint64_t step_stop = state.stop_revision;
  const std::uint64_t step_pc = state.pc;
  complete(engine.step_instruction(false), 10s, "step remote instruction");
  state = wait_for_state(engine, engine.snapshot(), [step_stop](const auto &next) {
    return next.state == debugger::SessionState::Error ||
           (next.state == debugger::SessionState::Stopped &&
            next.stop_revision > step_stop);
  });
  require(state.state == debugger::SessionState::Stopped && state.pc != step_pc,
          "remote instruction step did not advance the PC");
  require(std::ranges::any_of(
              state.instructions,
              [&state](const debugger::InstructionRow &instruction) {
                return instruction.address == state.pc;
              }),
          "remote instruction step did not refresh the PC row");

  complete(engine.continue_execution(), 10s, "continue remote target to exit");
  state = wait_for_state(engine, engine.snapshot(), [](const auto &candidate) {
    return candidate.state == debugger::SessionState::Exited ||
           candidate.state == debugger::SessionState::Error;
  });
  require(state.state == debugger::SessionState::Exited && state.exit_status == 0,
          "remote CTF! target did not exit with status zero");
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s X86_64_ELF LLDB_SERVER\n", argv[0]);
    return 2;
  }
  try {
    exercise_remote(argv[1], argv[2]);
  } catch (const std::exception &error) {
    std::fprintf(stderr, "remote test failure: %s\n", error.what());
    return 1;
  }
  return 0;
}
