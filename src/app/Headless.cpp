#include "app/Headless.h"
#include "app/AppActions.h"
#include "backend/decompiler/DecompilerEngine.h"
#include "backend/lldb/LldbEngine.h"
#include "localization/Localization.h"
#include "plugins/PluginApi.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace mydbg::app {

using namespace std::chrono_literals;

void print_headless_stop(const debugger::SessionSnapshot &snapshot) {
  std::printf(l10n::text(l10n::Key::HeadlessSnapshotState),
              debugger::to_string(snapshot.state), snapshot.generation,
              snapshot.stop_revision);
  std::printf(l10n::text(l10n::Key::HeadlessSnapshotTarget),
              snapshot.target_path.c_str(), snapshot.target_triple.c_str(),
              snapshot.architecture.c_str(), snapshot.byte_order.c_str(),
              snapshot.address_byte_size);
  std::printf(l10n::text(l10n::Key::HeadlessSnapshotProcess),
              snapshot.process_id, snapshot.thread_id, snapshot.pc, snapshot.sp,
              snapshot.stop_reason.c_str());
  std::printf(l10n::text(l10n::Key::HeadlessSnapshotDataCounts),
              snapshot.registers.size(), snapshot.instructions.size(),
              snapshot.memory.size());
  for (const auto &instruction : snapshot.instructions) {
    std::printf("0x%" PRIx64 ": %-20s %s %s\n", instruction.address,
                bytes_as_hex(instruction.bytes).c_str(),
                instruction.mnemonic.c_str(), instruction.operands.c_str());
  }
}

template <typename Predicate>
std::optional<debugger::SessionSnapshot>
wait_for_snapshot(debugger::LldbEngine &engine, Predicate &&predicate) {
  debugger::SessionSnapshot current = engine.snapshot();
  const auto deadline = std::chrono::steady_clock::now() + 15s;
  while (!predicate(current)) {
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
    if (remaining <= 0ms) {
      return std::nullopt;
    }
    const auto update = engine.wait_for_update(current.revision, remaining);
    if (!update) {
      return std::nullopt;
    }
    current = *update;
  }
  return current;
}

static std::optional<debugger::SessionSnapshot>
wait_for_state(debugger::LldbEngine &engine, debugger::SessionState state,
               bool stop_on_error = false) {
  return wait_for_snapshot(
      engine,
      [state, stop_on_error](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == state ||
               (stop_on_error &&
                snapshot.state == debugger::SessionState::Error);
      });
}

static std::optional<debugger::SessionSnapshot>
command_contains(debugger::LldbEngine &engine, std::string command,
                 std::string_view expected) {
  const std::size_t previous_size = engine.snapshot().console_output.size();
  engine.execute_command(std::move(command));
  return wait_for_snapshot(
      engine,
      [previous_size, expected](const debugger::SessionSnapshot &snapshot) {
        return snapshot.console_output.size() > previous_size &&
               snapshot.console_output.find(expected, previous_size) !=
                   std::string::npos;
      });
}

bool decompiler_ready(const debugger::DecompilerSnapshot &snapshot) {
  return !snapshot.loading &&
         (!snapshot.lines.empty() || !snapshot.error.empty());
}

template <typename Predicate>
std::shared_ptr<const debugger::DecompilerSnapshot>
wait_for_decompiler(debugger::DecompilerEngine &engine, Predicate &&predicate) {
  const auto deadline = std::chrono::steady_clock::now() + 15s;
  while (std::chrono::steady_clock::now() < deadline) {
    std::shared_ptr<const debugger::DecompilerSnapshot> snapshot =
        engine.snapshot();
    if (predicate(*snapshot)) {
      return snapshot;
    }
    std::this_thread::sleep_for(10ms);
  }
  return {};
}

bool verify_step_into_decompiler(const char *executable,
                                 debugger::LldbEngine &engine,
                                 debugger::DecompilerEngine &decompiler) {
  engine.launch(executable);

  const auto initial_stop =
      wait_for_state(engine, debugger::SessionState::Stopped, true);
  if (!initial_stop || initial_stop->state != debugger::SessionState::Stopped ||
      !initial_stop->has_pc_file_address) {
    std::fputs(l10n::text(l10n::Key::HeadlessStepIntoSetupFailed), stderr);
    return false;
  }

  const std::string initial_module = initial_stop->pc_module_path.empty()
                                         ? std::string{executable}
                                         : initial_stop->pc_module_path;
  request_decompilation(decompiler, *initial_stop, initial_module,
                        initial_stop->pc_file_address, initial_stop->pc);
  const auto caller = wait_for_decompiler(decompiler, decompiler_ready);
  if (!caller || !caller->error.empty() || caller->lines.empty()) {
    std::fputs(l10n::text(l10n::Key::HeadlessStepIntoCallerDecompilationFailed),
               stderr);
    return false;
  }

  const auto call_instruction = std::find_if(
      initial_stop->instructions.begin(), initial_stop->instructions.end(),
      [](const debugger::InstructionRow &instruction) {
        return instruction.mnemonic.starts_with("call");
      });
  if (call_instruction == initial_stop->instructions.end()) {
    std::fputs(l10n::text(l10n::Key::HeadlessStepIntoCallInstructionMissing),
               stderr);
    return false;
  }

  debugger::SessionSnapshot current = *initial_stop;
  while (current.pc != call_instruction->address) {
    const std::uint64_t revision = current.stop_revision;
    engine.step_instruction(false);
    const auto next = wait_for_snapshot(
        engine, [revision](const debugger::SessionSnapshot &snapshot) {
          return snapshot.state == debugger::SessionState::Stopped &&
                 snapshot.stop_revision != revision;
        });
    if (!next || !next->has_pc_file_address) {
      std::fputs(l10n::text(l10n::Key::HeadlessStepIntoCallSiteUnreachable),
                 stderr);
      return false;
    }
    current = *next;
    request_decompilation(decompiler, current, initial_module,
                          current.pc_file_address, current.pc);
  }

  const std::uint64_t call_revision = current.stop_revision;
  engine.step_instruction(false);
  const auto callee_stop = wait_for_snapshot(
      engine, [call_revision, call_address = call_instruction->address](
                  const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != call_revision &&
               snapshot.pc != call_address;
      });
  if (!callee_stop || !callee_stop->has_pc_file_address) {
    std::fputs(l10n::text(l10n::Key::HeadlessStepIntoCalleeNotEntered), stderr);
    return false;
  }

  const std::string callee_module = callee_stop->pc_module_path.empty()
                                        ? std::string{executable}
                                        : callee_stop->pc_module_path;
  request_decompilation(decompiler, *callee_stop, callee_module,
                        callee_stop->pc_file_address, callee_stop->pc);
  const auto callee = wait_for_decompiler(
      decompiler, [caller_function = caller->function_file_address](
                      const debugger::DecompilerSnapshot &snapshot) {
        return decompiler_ready(snapshot) &&
               snapshot.function_file_address != caller_function;
      });
  if (!callee || !callee->error.empty() || callee->lines.empty() ||
      callee->function_file_address == caller->function_file_address) {
    std::fputs(l10n::text(l10n::Key::HeadlessStepIntoDecompilerStayedOnCaller),
               stderr);
    return false;
  }
  engine.terminate();
  if (!wait_for_state(engine, debugger::SessionState::Exited)) {
    std::fputs(l10n::text(l10n::Key::HeadlessStepIntoTerminationFailed),
               stderr);
    return false;
  }

  std::printf(l10n::text(l10n::Key::HeadlessStepIntoDecompilerSummary),
              caller->function_file_address, callee->function_file_address);
  return true;
}

int run_headless(const char *executable, const char *attach_executable) {
  debugger::plugins::PluginLoader plugin_loader;
  load_plugins(plugin_loader);
  debugger::LldbEngine engine;
  debugger::DecompilerEngine decompiler;
  if (!verify_step_into_decompiler(executable, engine, decompiler)) {
    return 30;
  }
  engine.launch(executable);

  const auto first_stop =
      wait_for_state(engine, debugger::SessionState::Stopped, true);
  if (!first_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessInitialStopTimeout), stderr);
    return 2;
  }
  if (first_stop->state == debugger::SessionState::Error) {
    std::fprintf(stderr, l10n::text(l10n::Key::HeadlessLldbError),
                 first_stop->error.c_str());
    return 3;
  }
  print_headless_stop(*first_stop);
  if (first_stop->registers.empty() || first_stop->instructions.empty() ||
      first_stop->breakpoints.empty() || first_stop->memory.empty() ||
      first_stop->memory_base != first_stop->pc) {
    std::fputs(l10n::text(l10n::Key::HeadlessInitialDebuggerDataMissing),
               stderr);
    return 4;
  }
  if (std::getenv("MYDBG_REQUIRE_TEST_PLUGIN") != nullptr) {
    engine.execute_command("plugin-ping native");
    if (!wait_for_snapshot(
            engine, [](const debugger::SessionSnapshot &snapshot) {
              return snapshot.console_output.find("plugin-pong state=stopped "
                                                  "arguments=native") !=
                     std::string::npos;
            })) {
      std::fputs(l10n::text(l10n::Key::HeadlessNativePluginDispatchFailed),
                 stderr);
      return 31;
    }
  }

  const std::array<std::pair<std::string, std::string_view>, 22>
      native_commands{{
          {"config", "architecture="},
          {"vmmap", "r-x"},
          {"piebase", "0x"},
          {"hexdump pc 16", "|"},
          {"telescope sp 2", " -> 0x"},
          {"p2p sp 2", " -> "},
          {"procinfo", "Pid:"},
          {"auxv", "AT_"},
          {"linkmap", executable},
          {"retaddr", "#1"},
          {"cyclic 16", "aaaabaaacaaadaaa"},
          {"syscalls write", "1 write"},
          {"heap_config", "allocator=glibc"},
          {"got " + std::string(executable), ".got"},
          {"gotplt " + std::string(executable), ".got"},
          {"plt " + std::string(executable), ".plt"},
          {"search -x \"7f 45 4c 46\" " + std::string(executable), "0x"},
          {"tls", "fs_base"},
          {"canary", "0x"},
          {"cstruct void* sp", "(void *)"},
          {"plist sp 0 1", "0: 0x"},
          {"elfsections", ".text"},
      }};
  for (const auto &[command, expected] : native_commands) {
    if (!command_contains(engine, command, expected)) {
      const debugger::SessionSnapshot snapshot = engine.snapshot();
      std::fprintf(stderr, l10n::text(l10n::Key::HeadlessNativeCommandFailed),
                   command.c_str(), static_cast<int>(expected.size()),
                   expected.data(), snapshot.console_output.c_str());
      return 32;
    }
  }
  engine.execute_command("theme light");
  if (!wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return !snapshot.theme_dark;
      })) {
    std::fputs(l10n::text(l10n::Key::HeadlessNativeThemeCommandFailed), stderr);
    return 33;
  }
  engine.execute_command("theme dark");
  if (!wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.theme_dark;
      })) {
    std::fputs(l10n::text(l10n::Key::HeadlessNativeThemeRestoreFailed), stderr);
    return 34;
  }

  if (first_stop->supports_intel_syntax) {
    const bool default_uses_att = std::any_of(
        first_stop->instructions.begin(), first_stop->instructions.end(),
        [](const debugger::InstructionRow &instruction) {
          return instruction.operands.find('%') != std::string::npos;
        });
    if (!first_stop->intel_syntax || default_uses_att) {
      std::fputs(l10n::text(l10n::Key::HeadlessIntelSyntaxNotDefault), stderr);
      return 5;
    }

    engine.set_intel_syntax(false);
    const auto att_snapshot = wait_for_snapshot(
        engine, [](const debugger::SessionSnapshot &snapshot) {
          return snapshot.state == debugger::SessionState::Stopped &&
                 !snapshot.intel_syntax;
        });
    const bool att_has_register_prefix =
        att_snapshot &&
        std::any_of(att_snapshot->instructions.begin(),
                    att_snapshot->instructions.end(),
                    [](const debugger::InstructionRow &instruction) {
                      return instruction.operands.find('%') !=
                             std::string::npos;
                    });
    if (!att_has_register_prefix) {
      std::fputs(l10n::text(l10n::Key::HeadlessAttSyntaxToggleFailed), stderr);
      return 6;
    }
    engine.set_intel_syntax(true);
    if (!wait_for_snapshot(
            engine, [](const debugger::SessionSnapshot &snapshot) {
              return snapshot.state == debugger::SessionState::Stopped &&
                     snapshot.intel_syntax;
            })) {
      std::fputs(l10n::text(l10n::Key::HeadlessIntelSyntaxRestoreTimeout),
                 stderr);
      return 7;
    }
  }

  engine.set_breakpoint("calculate");
  const auto breakpoint_snapshot =
      wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return std::any_of(snapshot.breakpoints.begin(),
                           snapshot.breakpoints.end(),
                           [](const debugger::BreakpointInfo &breakpoint) {
                             return breakpoint.description.find("calculate") !=
                                        std::string::npos &&
                                    !breakpoint.addresses.empty();
                           });
      });
  if (!breakpoint_snapshot) {
    std::fputs(l10n::text(l10n::Key::HeadlessCalculateBreakpointUnresolved),
               stderr);
    return 8;
  }
  const auto breakpoint = std::find_if(
      breakpoint_snapshot->breakpoints.begin(),
      breakpoint_snapshot->breakpoints.end(),
      [](const debugger::BreakpointInfo &candidate) {
        return candidate.description.find("calculate") != std::string::npos;
      });
  const std::uint32_t calculate_breakpoint_id = breakpoint->id;

  engine.set_breakpoint_enabled(calculate_breakpoint_id, false);
  if (!wait_for_snapshot(
          engine,
          [calculate_breakpoint_id](const debugger::SessionSnapshot &snapshot) {
            const auto item = std::find_if(
                snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
                [calculate_breakpoint_id](
                    const debugger::BreakpointInfo &candidate) {
                  return candidate.id == calculate_breakpoint_id;
                });
            return item != snapshot.breakpoints.end() && !item->enabled;
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessBreakpointDisableFailed), stderr);
    return 9;
  }
  engine.set_breakpoint_enabled(calculate_breakpoint_id, true);
  if (!wait_for_snapshot(
          engine,
          [calculate_breakpoint_id](const debugger::SessionSnapshot &snapshot) {
            const auto item = std::find_if(
                snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
                [calculate_breakpoint_id](
                    const debugger::BreakpointInfo &candidate) {
                  return candidate.id == calculate_breakpoint_id;
                });
            return item != snapshot.breakpoints.end() && item->enabled;
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessBreakpointEnableFailed), stderr);
    return 10;
  }

  engine.read_memory(first_stop->pc);
  if (!wait_for_snapshot(
          engine, [address = first_stop->pc](
                      const debugger::SessionSnapshot &snapshot) {
            return snapshot.memory_base == address && !snapshot.memory.empty();
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessAddressMemoryNavigationFailed),
               stderr);
    return 11;
  }

  engine.execute_command("help");
  if (!wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.console_output.find("Debugger commands:") !=
               std::string::npos;
      })) {
    std::fputs(l10n::text(l10n::Key::HeadlessCommandHelpFailed), stderr);
    return 12;
  }
  engine.execute_command("target list");
  const auto fallback_snapshot =
      wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.console_output.find("> target list") !=
                   std::string::npos &&
               snapshot.console_output.find("Current targets:") !=
                   std::string::npos;
      });
  if (!fallback_snapshot) {
    const debugger::SessionSnapshot snapshot = engine.snapshot();
    std::fprintf(stderr,
                 l10n::text(l10n::Key::HeadlessLldbCommandFallbackFailed),
                 snapshot.console_output.c_str());
    return 13;
  }

  engine.continue_execution();
  const auto calculate_stop =
      wait_for_snapshot(engine, [revision = first_stop->stop_revision](
                                    const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != revision &&
               std::any_of(snapshot.breakpoints.begin(),
                           snapshot.breakpoints.end(),
                           [](const debugger::BreakpointInfo &breakpoint_info) {
                             return breakpoint_info.hit_count != 0;
                           });
      });
  if (!calculate_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessCalculateBreakpointNotHit),
               stderr);
    return 14;
  }
  if (!calculate_stop->has_pc_file_address) {
    std::fputs(l10n::text(l10n::Key::HeadlessProgramCounterFileMappingMissing),
               stderr);
    return 24;
  }
  request_decompilation(decompiler, *calculate_stop, executable,
                        calculate_stop->pc_file_address, calculate_stop->pc);
  const auto decompiled = wait_for_decompiler(decompiler, decompiler_ready);
  if (!decompiled || !decompiled->error.empty() || decompiled->lines.empty()) {
    std::fprintf(stderr,
                 l10n::text(l10n::Key::HeadlessGhidraDecompilationFailed),
                 decompiled ? decompiled->error.c_str()
                            : l10n::text(l10n::Key::HeadlessTimedOut));
    return 25;
  }
  if (decompiled->generation != calculate_stop->generation ||
      decompiled->requested_file_address != calculate_stop->pc_file_address ||
      decompiled->requested_load_address != calculate_stop->pc ||
      decompiled->module_id.empty()) {
    std::fputs(l10n::text(l10n::Key::HeadlessDecompilerIdentityNotPreserved),
               stderr);
    return 98;
  }
  const bool mentions_calculate =
      std::any_of(decompiled->lines.begin(), decompiled->lines.end(),
                  [](const debugger::DecompiledLine &line) {
                    return line.text.find("calculate") != std::string::npos;
                  });
  if (!mentions_calculate) {
    std::fputs(l10n::text(l10n::Key::HeadlessDecompilerSelectedFunctionMissing),
               stderr);
    return 26;
  }
  std::printf(l10n::text(l10n::Key::HeadlessDecompilerFunctionSummary),
              decompiled->function_file_address, decompiled->lines.size());

  const auto navigable_line =
      std::find_if(decompiled->lines.begin(), decompiled->lines.end(),
                   [address = calculate_stop->pc_file_address](
                       const debugger::DecompiledLine &line) {
                     return std::any_of(line.file_addresses.begin(),
                                        line.file_addresses.end(),
                                        [address](std::uint64_t candidate) {
                                          return candidate != address;
                                        });
                   });
  if (navigable_line != decompiled->lines.end()) {
    const auto file_address = *std::find_if(
        navigable_line->file_addresses.begin(),
        navigable_line->file_addresses.end(),
        [address = calculate_stop->pc_file_address](std::uint64_t candidate) {
          return candidate != address;
        });
    const std::uint64_t load_address =
        file_address + calculate_stop->pc_module_load_bias;
    engine.read_instructions(load_address);
    if (!wait_for_snapshot(
            engine, [load_address](const debugger::SessionSnapshot &snapshot) {
              return !snapshot.instructions.empty() &&
                     snapshot.instructions.front().address == load_address;
            })) {
      std::fputs(
          l10n::text(l10n::Key::HeadlessDecompilerDisassemblyNavigationFailed),
          stderr);
      return 27;
    }
  }

  engine.step_instruction(false);
  const auto step_into_stop = wait_for_snapshot(
      engine,
      [revision = calculate_stop->stop_revision,
       pc = calculate_stop->pc](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != revision && snapshot.pc != pc;
      });
  if (!step_into_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessInstructionStepIntoFailed),
               stderr);
    return 15;
  }
  if (!step_into_stop->has_pc_file_address) {
    std::fputs(l10n::text(l10n::Key::HeadlessStepDecompilerMappingLost),
               stderr);
    return 28;
  }
  request_decompilation(decompiler, *step_into_stop, executable,
                        step_into_stop->pc_file_address, step_into_stop->pc);
  const auto step_decompiled =
      wait_for_decompiler(decompiler, decompiler_ready);
  if (!step_decompiled || !step_decompiled->error.empty() ||
      step_into_stop->pc_file_address <
          step_decompiled->function_min_file_address ||
      step_into_stop->pc_file_address >=
          step_decompiled->function_max_file_address) {
    std::fputs(
        l10n::text(l10n::Key::HeadlessStepDecompilerSynchronizationFailed),
        stderr);
    return 29;
  }

  engine.step_instruction(true);
  const auto step_over_stop = wait_for_snapshot(
      engine,
      [revision = step_into_stop->stop_revision,
       pc = step_into_stop->pc](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != revision && snapshot.pc != pc;
      });
  if (!step_over_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessInstructionStepOverFailed),
               stderr);
    return 16;
  }
  const auto run_to_instruction = std::find_if(
      step_over_stop->instructions.begin(), step_over_stop->instructions.end(),
      [pc = step_over_stop->pc](const debugger::InstructionRow &row) {
        return row.address > pc;
      });
  if (run_to_instruction == step_over_stop->instructions.end()) {
    std::fputs(l10n::text(l10n::Key::HeadlessRunToCursorInstructionMissing),
               stderr);
    return 17;
  }

  const std::uint64_t run_to_address = run_to_instruction->address;
  engine.run_to_address(run_to_address);
  const auto run_to_stop = wait_for_snapshot(
      engine, [revision = step_over_stop->stop_revision,
               run_to_address](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != revision &&
               snapshot.pc == run_to_address;
      });
  if (!run_to_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessRunToCursorFailed), stderr);
    return 18;
  }

  engine.execute_command("dump rsp");
  const auto dump_snapshot =
      wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.memory_base == snapshot.sp &&
               !snapshot.memory.empty() &&
               snapshot.console_output.find("> dump rsp") != std::string::npos;
      });
  if (!dump_snapshot) {
    std::fputs(l10n::text(l10n::Key::HeadlessRegisterMemoryNavigationFailed),
               stderr);
    return 15;
  }

  engine.execute_command("bc " + std::to_string(calculate_breakpoint_id));
  if (!wait_for_snapshot(
          engine,
          [calculate_breakpoint_id](const debugger::SessionSnapshot &snapshot) {
            return std::none_of(
                snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
                [calculate_breakpoint_id](
                    const debugger::BreakpointInfo &breakpoint_info) {
                  return breakpoint_info.id == calculate_breakpoint_id;
                });
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessBreakpointDeleteCommandFailed),
               stderr);
    return 16;
  }

  engine.continue_execution();
  const auto exited =
      wait_for_state(engine, debugger::SessionState::Exited, true);
  if (!exited || exited->state != debugger::SessionState::Exited) {
    std::fputs(l10n::text(l10n::Key::HeadlessDebuggeeExitFailed), stderr);
    return 17;
  }
  std::printf(l10n::text(l10n::Key::HeadlessDebuggeeExitSummary),
              exited->exit_status, exited->process_output.c_str());
  if (exited->exit_status != 0 ||
      exited->process_output.find("debuggee result=41") == std::string::npos) {
    return 21;
  }

  engine.execute_command(std::string{"file "} + executable);
  const auto reloaded =
      wait_for_state(engine, debugger::SessionState::TargetLoaded);
  if (!reloaded) {
    std::fputs(l10n::text(l10n::Key::HeadlessFileTargetSelectionFailed),
               stderr);
    return 22;
  }
  engine.execute_command("set args");
  engine.execute_command("starti");
  const auto entry_stop =
      wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.process_id != 0;
      });
  if (!entry_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessEntryLaunchFailed), stderr);
    return 23;
  }
  engine.terminate();
  if (!wait_for_state(engine, debugger::SessionState::Exited)) {
    std::fputs(l10n::text(l10n::Key::HeadlessEntryTerminationFailed), stderr);
    return 24;
  }
  engine.execute_command("start");
  const auto main_stop =
      wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               std::any_of(snapshot.threads.begin(), snapshot.threads.end(),
                           [](const debugger::ThreadInfo &thread) {
                             return thread.selected && !thread.frames.empty() &&
                                    thread.frames.front().function == "main";
                           });
      });
  if (!main_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessMainLaunchFailed), stderr);
    return 25;
  }
  engine.execute_command("nextcall");
  const auto call_stop =
      wait_for_snapshot(engine, [revision = main_stop->stop_revision](
                                    const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != revision;
      });
  if (!call_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessNextCallNavigationFailed), stderr);
    return 26;
  }
  engine.execute_command("nextret");
  if (!wait_for_snapshot(
          engine, [revision = call_stop->stop_revision](
                      const debugger::SessionSnapshot &snapshot) {
            return snapshot.state == debugger::SessionState::Stopped &&
                   snapshot.stop_revision != revision;
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessNextReturnNavigationFailed),
               stderr);
    return 26;
  }
  engine.terminate();
  if (!wait_for_state(engine, debugger::SessionState::Exited)) {
    const debugger::SessionSnapshot failed = engine.snapshot();
    std::fprintf(stderr, l10n::text(l10n::Key::HeadlessMainTerminationFailed),
                 debugger::to_string(failed.state), failed.error.c_str());
    return 26;
  }
  engine.execute_command("sstart");
  const auto libc_stop =
      wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               std::any_of(snapshot.threads.begin(), snapshot.threads.end(),
                           [](const debugger::ThreadInfo &thread) {
                             return thread.selected && !thread.frames.empty() &&
                                    thread.frames.front().function.find(
                                        "__libc_start_main") !=
                                        std::string::npos;
                           });
      });
  if (!libc_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessLibcStartupLaunchFailed), stderr);
    return 27;
  }
  engine.terminate();
  if (!wait_for_state(engine, debugger::SessionState::Exited)) {
    std::fputs(l10n::text(l10n::Key::HeadlessLibcStartupTerminationFailed),
               stderr);
    return 28;
  }
  if (attach_executable != nullptr) {
    engine.execute_command(std::string{"file "} + attach_executable);
    if (!wait_for_state(engine, debugger::SessionState::TargetLoaded)) {
      std::fputs(l10n::text(l10n::Key::HeadlessAttachTargetReloadFailed),
                 stderr);
      return 29;
    }
    const pid_t child = ::fork();
    if (child == 0) {
      ::execl(attach_executable, attach_executable,
              static_cast<char *>(nullptr));
      ::_exit(127);
    }
    if (child < 0) {
      std::perror("fork");
      return 29;
    }
    std::this_thread::sleep_for(100ms);
    engine.execute_command("attachp " +
                           std::to_string(static_cast<std::uint64_t>(child)));
    const auto attached = wait_for_snapshot(
        engine, [child](const debugger::SessionSnapshot &snapshot) {
          return snapshot.state == debugger::SessionState::Stopped &&
                 snapshot.process_id == static_cast<std::uint64_t>(child);
        });
    if (!attached) {
      ::kill(child, SIGKILL);
      ::waitpid(child, nullptr, 0);
      std::fputs(l10n::text(l10n::Key::HeadlessProcessAttachmentFailed),
                 stderr);
      return 29;
    }
    engine.terminate();
    const bool attached_exited =
        wait_for_state(engine, debugger::SessionState::Exited).has_value();
    ::kill(child, SIGKILL);
    ::waitpid(child, nullptr, 0);
    if (!attached_exited) {
      std::fputs(
          l10n::text(l10n::Key::HeadlessAttachedProcessTerminationFailed),
          stderr);
      return 29;
    }
  }
  return 0;
}

int run_condition_headless(const char *executable) {
  debugger::LldbEngine engine;
  engine.launch(executable);
  const auto initial =
      wait_for_state(engine, debugger::SessionState::Stopped, true);
  if (!initial || initial->state != debugger::SessionState::Stopped) {
    std::fputs(l10n::text(l10n::Key::HeadlessConditionInitialStopFailed),
               stderr);
    return 50;
  }
  const auto invalid_breakpoint =
      engine.set_conditional_breakpoint("condition_secondary", "if(rax ===)");
  const bool invalid_rejected =
      invalid_breakpoint.wait_for(std::chrono::seconds{5}) &&
      !invalid_breakpoint.get().success;
  const auto rejected = engine.snapshot();
  if (!invalid_rejected ||
      std::any_of(rejected.breakpoints.begin(), rejected.breakpoints.end(),
                  [](const debugger::BreakpointInfo &breakpoint) {
                    return breakpoint.description.find("condition_secondary") !=
                           std::string::npos;
                  })) {
    std::fputs(
        l10n::text(l10n::Key::HeadlessAtomicConditionalBreakpointNotRejected),
        stderr);
    return 60;
  }

  const auto install =
      [&engine](std::string_view symbol,
                std::string_view condition) -> std::optional<std::uint32_t> {
    engine.set_conditional_breakpoint(std::string{symbol},
                                      std::string{condition});
    const auto breakpoint_snapshot = wait_for_snapshot(
        engine, [symbol, condition](const debugger::SessionSnapshot &snapshot) {
          return std::any_of(
              snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
              [symbol, condition](const debugger::BreakpointInfo &breakpoint) {
                return breakpoint.description.find(symbol) !=
                           std::string::npos &&
                       !breakpoint.addresses.empty() &&
                       breakpoint.script_condition == condition;
              });
        });
    if (!breakpoint_snapshot)
      return std::nullopt;
    const auto breakpoint = std::find_if(
        breakpoint_snapshot->breakpoints.begin(),
        breakpoint_snapshot->breakpoints.end(),
        [symbol](const debugger::BreakpointInfo &candidate) {
          return candidate.description.find(symbol) != std::string::npos;
        });
    if (breakpoint == breakpoint_snapshot->breakpoints.end())
      return std::nullopt;
    const std::uint32_t id = breakpoint->id;
    return id;
  };

  engine.set_breakpoint("condition_target");
  const auto target_snapshot =
      wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return std::any_of(
            snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
            [](const debugger::BreakpointInfo &breakpoint) {
              return breakpoint.description.find("condition_target") !=
                         std::string::npos &&
                     !breakpoint.addresses.empty();
            });
      });
  if (!target_snapshot) {
    std::fputs(
        l10n::text(l10n::Key::HeadlessConditionTargetBreakpointUnresolved),
        stderr);
    return 51;
  }
  const auto target_breakpoint = std::find_if(
      target_snapshot->breakpoints.begin(), target_snapshot->breakpoints.end(),
      [](const debugger::BreakpointInfo &breakpoint) {
        return breakpoint.description.find("condition_target") !=
               std::string::npos;
      });
  const std::uint32_t target_id = target_breakpoint->id;

  const auto invalid_condition =
      engine.set_breakpoint_script(target_id, "if(rax ===)");
  if (!invalid_condition.wait_for(std::chrono::seconds{5}) ||
      invalid_condition.get().success) {
    std::fputs(l10n::text(l10n::Key::HeadlessInvalidScriptedConditionAccepted),
               stderr);
    return 52;
  }

  constexpr std::string_view target_condition =
      "if(($rdi >= 3 && rdi <= 3) && rdi != 2 && !(rdi < 3) && "
      "masked_cmp(valueAt(rsi), \"DE AD ?? EF\") && "
      "strcmp(valueAt(rdx) == \"I am a string\"))";
  engine.set_breakpoint_script(target_id, std::string{target_condition});
  if (!wait_for_snapshot(
          engine, [target_id, target_condition](
                      const debugger::SessionSnapshot &snapshot) {
            const auto item = std::find_if(
                snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
                [target_id](const debugger::BreakpointInfo &entry) {
                  return entry.id == target_id;
                });
            return item != snapshot.breakpoints.end() &&
                   item->script_condition == target_condition;
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessTargetConditionInstallFailed),
               stderr);
    return 53;
  }

  const auto secondary_id = install("condition_secondary",
                                    "if((rdi === 0x2A && rsi == 42) || false)");
  const auto truthy_id = install("condition_truthy", "if(rdi && true)");
  const auto error_id =
      install("condition_error_target", "missing_register == 1");
  if (!secondary_id || !truthy_id || !error_id) {
    std::fputs(l10n::text(l10n::Key::HeadlessScriptedBreakpointInstallFailed),
               stderr);
    return 54;
  }

  const auto wait_for_breakpoint = [&engine](std::uint32_t id,
                                             std::uint32_t hits,
                                             std::uint64_t previous_revision) {
    return wait_for_snapshot(
        engine, [id, hits,
                 previous_revision](const debugger::SessionSnapshot &snapshot) {
          if (snapshot.state != debugger::SessionState::Stopped ||
              snapshot.stop_revision == previous_revision)
            return false;
          const auto item = std::find_if(
              snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
              [id](const debugger::BreakpointInfo &entry) {
                return entry.id == id;
              });
          return item != snapshot.breakpoints.end() &&
                 item->hit_count == hits && item->script_error.empty();
        });
  };

  engine.continue_execution();
  const auto target_match =
      wait_for_breakpoint(target_id, 4, initial->stop_revision);
  if (!target_match) {
    std::fputs(l10n::text(l10n::Key::HeadlessCombinedConditionMatchFailed),
               stderr);
    return 55;
  }

  engine.continue_execution();
  const auto secondary_match =
      wait_for_breakpoint(*secondary_id, 1, target_match->stop_revision);
  if (!secondary_match) {
    std::fputs(l10n::text(l10n::Key::HeadlessNumericConditionMatchFailed),
               stderr);
    return 56;
  }

  engine.continue_execution();
  const auto truthy_match =
      wait_for_breakpoint(*truthy_id, 1, secondary_match->stop_revision);
  if (!truthy_match) {
    std::fputs(l10n::text(l10n::Key::HeadlessTruthyConditionMatchFailed),
               stderr);
    return 57;
  }

  engine.continue_execution();
  const auto evaluation_error = wait_for_snapshot(
      engine, [id = *error_id, revision = truthy_match->stop_revision](
                  const debugger::SessionSnapshot &snapshot) {
        if (snapshot.state != debugger::SessionState::Stopped ||
            snapshot.stop_revision == revision)
          return false;
        const auto item = std::find_if(
            snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
            [id](const debugger::BreakpointInfo &entry) {
              return entry.id == id;
            });
        return item != snapshot.breakpoints.end() &&
               !item->script_error.empty();
      });
  if (!evaluation_error) {
    std::fputs(l10n::text(l10n::Key::HeadlessConditionEvaluationDidNotStop),
               stderr);
    return 58;
  }

  engine.continue_execution();
  if (!wait_for_state(engine, debugger::SessionState::Exited)) {
    std::fputs(l10n::text(l10n::Key::HeadlessConditionDebuggeeExitFailed),
               stderr);
    return 59;
  }
  std::fputs(l10n::text(l10n::Key::HeadlessScriptedConditionsSummary), stdout);
  return 0;
}

int run_heap_headless(const char *executable) {
  debugger::LldbEngine engine;
  engine.launch(executable);
  const auto initial =
      wait_for_state(engine, debugger::SessionState::Stopped, true);
  if (!initial || initial->state != debugger::SessionState::Stopped) {
    std::fputs(l10n::text(l10n::Key::HeadlessHeapInitialStopFailed), stderr);
    return 40;
  }
  engine.set_breakpoint("heap_ready");
  if (!wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return std::any_of(snapshot.breakpoints.begin(),
                           snapshot.breakpoints.end(),
                           [](const debugger::BreakpointInfo &breakpoint) {
                             return breakpoint.description.find("heap_ready") !=
                                        std::string::npos &&
                                    !breakpoint.addresses.empty();
                           });
      })) {
    std::fputs(l10n::text(l10n::Key::HeadlessHeapReadyBreakpointUnresolved),
               stderr);
    return 41;
  }
  engine.continue_execution();
  const auto heap_stop =
      wait_for_snapshot(engine, [revision = initial->stop_revision](
                                    const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != revision &&
               !snapshot.heap_chunks.empty();
      });
  if (!heap_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessHeapChunksMissing), stderr);
    return 42;
  }
  if (std::none_of(
          heap_stop->heap_chunks.begin(), heap_stop->heap_chunks.end(),
          [](const debugger::HeapChunkInfo &chunk) { return !chunk.in_use; })) {
    std::fputs(l10n::text(l10n::Key::HeadlessFreedHeapChunkMissing), stderr);
    return 43;
  }

  if (!command_contains(engine, "heap", "size=0x") ||
      !command_contains(engine, "bins", "free") ||
      !command_contains(engine, "vis_heap_chunks", "-> next")) {
    std::fputs(l10n::text(l10n::Key::HeadlessHeapCommandOutputFailed), stderr);
    return 44;
  }
  if (!command_contains(engine, "arenas", "main heap chunks=")) {
    std::fputs(l10n::text(l10n::Key::HeadlessArenaInspectionFailed), stderr);
    return 44;
  }
  char fake_fast_command[96]{};
  std::snprintf(fake_fast_command, sizeof(fake_fast_command),
                "find_fake_fast 0x%" PRIx64,
                heap_stop->heap_chunks.front().address + 0x20);
  if (!command_contains(engine, fake_fast_command, "chunk")) {
    std::fputs(l10n::text(l10n::Key::HeadlessFakeFastChunkSearchFailed),
               stderr);
    return 44;
  }

  const auto retained =
      std::find_if(heap_stop->heap_chunks.begin(), heap_stop->heap_chunks.end(),
                   [](const debugger::HeapChunkInfo &chunk) {
                     return chunk.in_use && chunk.size > 0x40;
                   });
  if (retained != heap_stop->heap_chunks.end()) {
    char command[96]{};
    std::snprintf(command, sizeof(command), "try_free 0x%" PRIx64,
                  retained->address + heap_stop->address_byte_size * 2);
    if (!command_contains(engine, command, "plausible free")) {
      std::fputs(l10n::text(l10n::Key::HeadlessTryFreeValidationFailed),
                 stderr);
      return 45;
    }
  }

  engine.read_memory(heap_stop->sp);
  const auto stack = wait_for_snapshot(
      engine,
      [address = heap_stop->sp](const debugger::SessionSnapshot &snapshot) {
        return snapshot.memory_base == address && snapshot.memory.size() >= 2;
      });
  if (!stack) {
    std::fputs(l10n::text(l10n::Key::HeadlessPatchStackBytesMissing), stderr);
    return 46;
  }
  const std::uint8_t original = stack->memory[0];
  const std::uint8_t original_next = stack->memory[1];
  const std::uint8_t replacement = static_cast<std::uint8_t>(original ^ 0xffU);
  const std::uint8_t replacement_next =
      static_cast<std::uint8_t>(original_next ^ 0xffU);
  char patch_command[96]{};
  std::snprintf(patch_command, sizeof(patch_command),
                "patch 0x%" PRIx64 " %02x %02x", stack->sp,
                static_cast<unsigned int>(replacement),
                static_cast<unsigned int>(replacement_next));
  engine.execute_command(patch_command);
  const auto patched =
      wait_for_snapshot(engine, [replacement, replacement_next](
                                    const debugger::SessionSnapshot &snapshot) {
        return snapshot.patches.size() == 1 && snapshot.memory.size() >= 2 &&
               snapshot.memory[0] == replacement &&
               snapshot.memory[1] == replacement_next;
      });
  char readback_command[96]{};
  std::snprintf(readback_command, sizeof(readback_command),
                "hexdump 0x%" PRIx64 " 1", stack->sp);
  char replacement_text[8]{};
  std::snprintf(replacement_text, sizeof(replacement_text), " %02x ",
                static_cast<unsigned int>(replacement));
  if (!patched ||
      !command_contains(engine, readback_command, replacement_text)) {
    const debugger::SessionSnapshot failed = engine.snapshot();
    std::fprintf(stderr, l10n::text(l10n::Key::HeadlessPatchReadbackFailed),
                 failed.console_output.c_str());
    return 47;
  }
  const std::uint8_t second_replacement =
      static_cast<std::uint8_t>(original ^ 0x7fU);
  std::snprintf(patch_command, sizeof(patch_command),
                "patch 0x%" PRIx64 " %02x", stack->sp,
                static_cast<unsigned int>(second_replacement));
  engine.execute_command(patch_command);
  const auto repatched =
      wait_for_snapshot(engine, [second_replacement, replacement_next](
                                    const debugger::SessionSnapshot &snapshot) {
        return snapshot.patches.size() == 1 && snapshot.memory.size() >= 2 &&
               snapshot.memory[0] == second_replacement &&
               snapshot.memory[1] == replacement_next &&
               snapshot.patches.front().replacement ==
                   std::vector<std::uint8_t>{second_replacement,
                                             replacement_next};
      });
  if (!repatched || repatched->patches.front().original !=
                        std::vector<std::uint8_t>{original, original_next}) {
    std::fputs(l10n::text(l10n::Key::HeadlessOverlappingPatchOriginalBytesLost),
               stderr);
    return 48;
  }
  engine.execute_command("patch_revert " +
                         std::to_string(repatched->patches.front().id));
  if (!wait_for_snapshot(
          engine,
          [original, original_next](const debugger::SessionSnapshot &snapshot) {
            return snapshot.patches.empty() && snapshot.memory.size() >= 2 &&
                   snapshot.memory[0] == original &&
                   snapshot.memory[1] == original_next;
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessPatchRevertFailed), stderr);
    return 49;
  }
  char original_text[8]{};
  std::snprintf(original_text, sizeof(original_text), " %02x ",
                static_cast<unsigned int>(original));
  if (!command_contains(engine, readback_command, original_text)) {
    std::fputs(l10n::text(l10n::Key::HeadlessPatchRevertReadbackFailed),
               stderr);
    return 49;
  }

  if (heap_stop->supports_intel_syntax) {
    const std::string assemble_command =
        "assemble " + address_specification(heap_stop->pc) + " int3";
    engine.execute_command(assemble_command);
    const auto assembled = wait_for_snapshot(
        engine,
        [address = heap_stop->pc](const debugger::SessionSnapshot &snapshot) {
          return snapshot.patches.size() == 1 &&
                 snapshot.patches.front().address == address &&
                 snapshot.patches.front().replacement ==
                     std::vector<std::uint8_t>{0xcc};
        });
    if (!assembled) {
      const debugger::SessionSnapshot failed = engine.snapshot();
      std::fprintf(stderr, l10n::text(l10n::Key::HeadlessIntelAssemblyFailed),
                   failed.console_output.c_str());
      return 50;
    }
    engine.execute_command("patch_revert " +
                           std::to_string(assembled->patches.front().id));
    if (!wait_for_snapshot(engine,
                           [](const debugger::SessionSnapshot &snapshot) {
                             return snapshot.patches.empty();
                           })) {
      std::fputs(
          l10n::text(l10n::Key::HeadlessAssembledInstructionRevertFailed),
          stderr);
      return 51;
    }
  }
  engine.terminate();
  if (!wait_for_state(engine, debugger::SessionState::Exited)) {
    std::fputs(l10n::text(l10n::Key::HeadlessHeapTerminationFailed), stderr);
    return 52;
  }
  return 0;
}

int run_scans_headless(const char *executable) {
  debugger::LldbEngine engine;
  engine.launch(executable);
  const auto initial =
      wait_for_state(engine, debugger::SessionState::Stopped, true);
  if (!initial || initial->state != debugger::SessionState::Stopped) {
    std::fputs(l10n::text(l10n::Key::HeadlessScanInitialStopFailed), stderr);
    return 70;
  }

  engine.scan_binary_strings(8, true);
  const auto strings =
      wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return std::any_of(
            snapshot.binary_strings.begin(), snapshot.binary_strings.end(),
            [](const debugger::BinaryStringInfo &result) {
              return result.value == "MYDBG_BINARY_STRING_SCAN_MARKER" &&
                     result.encoding == "ASCII" && result.has_file_address &&
                     result.has_load_address;
            });
      });
  if (!strings) {
    const debugger::SessionSnapshot failed = engine.snapshot();
    std::fprintf(stderr, l10n::text(l10n::Key::HeadlessBinaryStringScanFailed),
                 failed.binary_strings_error.c_str());
    return 71;
  }

  engine.set_breakpoint("scan_checkpoint");
  if (!wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return std::any_of(
            snapshot.breakpoints.begin(), snapshot.breakpoints.end(),
            [](const debugger::BreakpointInfo &breakpoint) {
              return breakpoint.description.find("scan_checkpoint") !=
                         std::string::npos &&
                     !breakpoint.addresses.empty();
            });
      })) {
    std::fputs(
        l10n::text(l10n::Key::HeadlessScanCheckpointBreakpointUnresolved),
        stderr);
    return 72;
  }
  const auto continue_to_checkpoint = [&engine](
                                          std::uint64_t previous_revision) {
    engine.continue_execution();
    return wait_for_snapshot(
        engine, [previous_revision](const debugger::SessionSnapshot &snapshot) {
          if (snapshot.state != debugger::SessionState::Stopped ||
              snapshot.stop_revision == previous_revision) {
            return false;
          }
          return std::any_of(
              snapshot.threads.begin(), snapshot.threads.end(),
              [](const debugger::ThreadInfo &thread) {
                return thread.selected &&
                       std::any_of(thread.frames.begin(), thread.frames.end(),
                                   [](const debugger::StackFrameInfo &frame) {
                                     return frame.function.find(
                                                "scan_checkpoint") !=
                                            std::string::npos;
                                   });
              });
        });
  };

  const auto first_checkpoint = continue_to_checkpoint(initial->stop_revision);
  if (!first_checkpoint) {
    const debugger::SessionSnapshot failed = engine.snapshot();
    std::fprintf(stderr,
                 l10n::text(l10n::Key::HeadlessFirstScanCheckpointNotReached),
                 debugger::to_string(failed.state), failed.stop_revision,
                 failed.error.c_str());
    for (const debugger::ThreadInfo &thread : failed.threads) {
      if (thread.selected && !thread.frames.empty()) {
        std::fprintf(stderr, l10n::text(l10n::Key::HeadlessSelectedFrame),
                     thread.frames.front().function.c_str());
      }
    }
    return 73;
  }
  const std::uint64_t unknown_revision = first_checkpoint->value_scan_revision;
  engine.start_value_scan(debugger::ValueScanType::Qword, {}, true, false,
                          true);
  const auto unknown_scan = wait_for_snapshot(
      engine, [unknown_revision](const debugger::SessionSnapshot &snapshot) {
        return snapshot.value_scan_revision > unknown_revision &&
               snapshot.value_scan_active &&
               snapshot.value_scan_error.empty() &&
               snapshot.value_scan_match_count != 0;
      });
  if (!unknown_scan) {
    const debugger::SessionSnapshot failed = engine.snapshot();
    std::fprintf(stderr,
                 l10n::text(l10n::Key::HeadlessUnknownInitialValueScanFailed),
                 failed.value_scan_error.c_str());
    return 74;
  }
  engine.reset_value_scan();
  const auto reset_scan =
      wait_for_snapshot(engine, [revision = unknown_scan->value_scan_revision](
                                    const debugger::SessionSnapshot &snapshot) {
        return snapshot.value_scan_revision > revision &&
               !snapshot.value_scan_active;
      });
  if (!reset_scan) {
    std::fputs(l10n::text(l10n::Key::HeadlessValueScanResetFailed), stderr);
    return 74;
  }
  const std::uint64_t first_scan_revision = reset_scan->value_scan_revision;
  engine.start_value_scan(debugger::ValueScanType::Dword, "0x13572468", false,
                          false, true);
  const auto first_scan = wait_for_snapshot(
      engine, [first_scan_revision](const debugger::SessionSnapshot &snapshot) {
        return snapshot.value_scan_revision > first_scan_revision &&
               snapshot.value_scan_active &&
               snapshot.value_scan_error.empty() &&
               snapshot.value_scan_match_count != 0;
      });
  if (!first_scan) {
    const debugger::SessionSnapshot failed = engine.snapshot();
    std::fprintf(stderr,
                 l10n::text(l10n::Key::HeadlessExactValueFirstScanFailed),
                 failed.value_scan_error.c_str());
    return 74;
  }
  constexpr std::string_view initial_value = "324478056";
  const auto initial_result =
      std::find_if(first_scan->value_scan_results.begin(),
                   first_scan->value_scan_results.end(),
                   [initial_value](const debugger::ValueScanResult &result) {
                     return result.current_value == initial_value;
                   });
  if (initial_result == first_scan->value_scan_results.end()) {
    std::fputs(l10n::text(l10n::Key::HeadlessInitialScanValueMissing), stderr);
    return 75;
  }
  const std::uint64_t value_address = initial_result->address;

  struct ScanStep {
    debugger::ValueScanComparison comparison;
    const char *previous;
    const char *current;
    l10n::Key checkpoint_error;
    int checkpoint_code;
    l10n::Key scan_error;
    int scan_code;
  };
  constexpr ScanStep steps[]{
      {debugger::ValueScanComparison::Changed, "324478056", "287454020",
       l10n::Key::HeadlessChangedValueCheckpointNotReached, 76,
       l10n::Key::HeadlessChangedValueScanFailed, 77},
      {debugger::ValueScanComparison::Decreased, "287454020", "270544960",
       l10n::Key::HeadlessDecreasedValueCheckpointNotReached, 78,
       l10n::Key::HeadlessDecreasedValueScanFailed, 79},
      {debugger::ValueScanComparison::Unchanged, "270544960", "270544960",
       l10n::Key::HeadlessUnchangedValueCheckpointNotReached, 78,
       l10n::Key::HeadlessUnchangedValueScanFailed, 79},
      {debugger::ValueScanComparison::Increased, "270544960", "1887473824",
       l10n::Key::HeadlessIncreasedValueCheckpointNotReached, 80,
       l10n::Key::HeadlessIncreasedValueScanFailed, 81},
  };
  std::uint64_t previous_stop = first_checkpoint->stop_revision;
  for (const auto &step : steps) {
    const auto checkpoint = continue_to_checkpoint(previous_stop);
    if (!checkpoint) {
      std::fputs(l10n::text(step.checkpoint_error), stderr);
      return step.checkpoint_code;
    }
    engine.next_value_scan(step.comparison, {});
    const auto scanned = wait_for_snapshot(
        engine, [revision = checkpoint->value_scan_revision, value_address,
                 &step](const debugger::SessionSnapshot &snapshot) {
          return snapshot.value_scan_revision > revision &&
                 std::any_of(snapshot.value_scan_results.begin(),
                             snapshot.value_scan_results.end(),
                             [value_address,
                              &step](const debugger::ValueScanResult &result) {
                               return result.address == value_address &&
                                      result.previous_value == step.previous &&
                                      result.current_value == step.current;
                             });
        });
    if (!scanned) {
      std::fputs(l10n::text(step.scan_error), stderr);
      return step.scan_code;
    }
    previous_stop = checkpoint->stop_revision;
  }

  engine.terminate();
  if (!wait_for_state(engine, debugger::SessionState::Exited)) {
    std::fputs(l10n::text(l10n::Key::HeadlessScanTerminationFailed), stderr);
    return 82;
  }
  std::fputs(l10n::text(l10n::Key::HeadlessScansSummary), stdout);
  return 0;
}
int run_stop_intelligence_headless(const char *executable) {
  debugger::LldbEngine engine;
  engine.launch(executable);
  const auto initial_stop =
      wait_for_state(engine, debugger::SessionState::Stopped);
  if (!initial_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessIntelligenceInitialStopFailed),
               stderr);
    return 83;
  }

  const std::size_t initial_breakpoint_count = initial_stop->breakpoints.size();
  engine.set_breakpoint("call_site_checkpoint");
  if (!wait_for_snapshot(
          engine, [initial_breakpoint_count](
                      const debugger::SessionSnapshot &snapshot) {
            return snapshot.breakpoints.size() > initial_breakpoint_count;
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessCallSiteBreakpointUnresolved),
               stderr);
    return 84;
  }
  engine.continue_execution();
  const auto wrapper_stop =
      wait_for_snapshot(engine, [revision = initial_stop->stop_revision](
                                    const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != revision &&
               snapshot.stop_reason.find("breakpoint") != std::string::npos;
      });
  if (!wrapper_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessCallSiteCheckpointNotReached),
               stderr);
    return 85;
  }

  debugger::SessionSnapshot call_state = *wrapper_stop;
  auto current_call = call_state.instructions.end();
  for (std::size_t steps = 0; steps < 16; ++steps) {
    current_call = std::find_if(
        call_state.instructions.begin(), call_state.instructions.end(),
        [&call_state](const debugger::InstructionRow &instruction) {
          return instruction.address == call_state.pc;
        });
    if (current_call != call_state.instructions.end() &&
        current_call->flow_kind == debugger::InstructionFlowKind::Call) {
      break;
    }
    const std::uint64_t revision = call_state.stop_revision;
    engine.step_instruction(false);
    const auto next = wait_for_snapshot(
        engine, [revision](const debugger::SessionSnapshot &snapshot) {
          return snapshot.state == debugger::SessionState::Stopped &&
                 snapshot.stop_revision != revision;
        });
    if (!next) {
      break;
    }
    call_state = *next;
  }
  if (current_call == call_state.instructions.end() ||
      current_call->flow_kind != debugger::InstructionFlowKind::Call ||
      current_call->arguments.size() < 6) {
    std::fputs(l10n::text(l10n::Key::HeadlessAbiCallArgumentDecodingIncomplete),
               stderr);
    return 96;
  }

  const std::uint64_t call_revision = call_state.stop_revision;
  const std::uint64_t call_address = call_state.pc;
  engine.step_instruction(false);
  const auto entry_stop = wait_for_snapshot(
      engine,
      [call_revision, call_address](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != call_revision &&
               snapshot.pc != call_address;
      });
  if (!entry_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessIntelligenceCheckpointNotEntered),
               stderr);
    return 97;
  }

  const auto entry_instruction = std::find_if(
      entry_stop->instructions.begin(), entry_stop->instructions.end(),
      [&entry_stop](const debugger::InstructionRow &instruction) {
        return instruction.address == entry_stop->pc;
      });
  if (entry_instruction == entry_stop->instructions.end() ||
      entry_instruction->resolved_operands.empty()) {
    std::fputs(l10n::text(l10n::Key::HeadlessOperandResolutionUnavailable),
               stderr);
    return 86;
  }

  const auto conditional = std::find_if(
      entry_stop->instructions.begin(), entry_stop->instructions.end(),
      [](const debugger::InstructionRow &instruction) {
        return instruction.flow_kind ==
               debugger::InstructionFlowKind::ConditionalJump;
      });
  if (conditional == entry_stop->instructions.end()) {
    std::fputs(l10n::text(l10n::Key::HeadlessFixtureConditionalBranchMissing),
               stderr);
    return 87;
  }
  const std::uint64_t branch_address = conditional->address;
  engine.run_to_address(branch_address);
  const auto branch_stop = wait_for_snapshot(
      engine, [branch_address, revision = entry_stop->stop_revision](
                  const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.stop_revision != revision &&
               snapshot.pc == branch_address;
      });
  if (!branch_stop) {
    std::fputs(l10n::text(l10n::Key::HeadlessConditionalBranchStopNotReached),
               stderr);
    return 88;
  }
  const auto current = std::find_if(
      branch_stop->instructions.begin(), branch_stop->instructions.end(),
      [branch_address](const debugger::InstructionRow &instruction) {
        return instruction.address == branch_address;
      });
  if (current == branch_stop->instructions.end() ||
      !current->branch.conditional || !current->branch.available ||
      current->branch.taken_target == 0 ||
      current->branch.fallthrough_target == 0) {
    std::fprintf(
        stderr, l10n::text(l10n::Key::HeadlessBranchIntelligenceIncomplete),
        current != branch_stop->instructions.end(),
        current != branch_stop->instructions.end() &&
            current->branch.conditional,
        current != branch_stop->instructions.end() && current->branch.available,
        current == branch_stop->instructions.end()
            ? 0
            : current->branch.taken_target,
        current == branch_stop->instructions.end()
            ? 0
            : current->branch.fallthrough_target,
        current == branch_stop->instructions.end()
            ? l10n::text(l10n::Key::HeadlessMissingInstruction)
            : current->branch.explanation.c_str());
    return 89;
  }
  const bool has_register_delta = std::any_of(
      branch_stop->registers.begin(), branch_stop->registers.end(),
      [](const debugger::RegisterValue &value) { return value.changed; });
  if (!has_register_delta || branch_stop->stop_history.size() < 2) {
    std::fputs(l10n::text(l10n::Key::HeadlessStopHistoryRegisterDeltasMissing),
               stderr);
    return 90;
  }

  const std::size_t insight_output_size = branch_stop->console_output.size();
  engine.execute_command("context insight");
  if (!wait_for_snapshot(
          engine,
          [insight_output_size](const debugger::SessionSnapshot &snapshot) {
            return snapshot.console_output.size() > insight_output_size &&
                   snapshot.console_output.substr(insight_output_size)
                           .find("[instruction insight]") !=
                       std::string::npos &&
                   snapshot.console_output.substr(insight_output_size)
                           .find("branch ") != std::string::npos;
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessContextBranchIntelligenceMissing),
               stderr);
    return 91;
  }

  engine.continue_execution();
  const auto crash =
      wait_for_snapshot(engine, [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped &&
               snapshot.crash.crashed;
      });
  if (!crash) {
    std::fputs(l10n::text(l10n::Key::HeadlessFixtureCrashNotTriaged), stderr);
    return 92;
  }
  const bool cyclic_register = std::any_of(
      crash->crash.cyclic_matches.begin(), crash->crash.cyclic_matches.end(),
      [](const debugger::CyclicMatch &match) {
        return match.source == "register r12";
      });
  if (!cyclic_register || crash->crash.signal_number == 0 ||
      crash->crash.summary.empty() || crash->stop_history.size() < 3) {
    std::fputs(l10n::text(l10n::Key::HeadlessCyclicCrashEvidenceIncomplete),
               stderr);
    return 93;
  }

  const std::size_t crash_output_size = crash->console_output.size();
  engine.execute_command("context crash");
  if (!wait_for_snapshot(
          engine,
          [crash_output_size](const debugger::SessionSnapshot &snapshot) {
            return snapshot.console_output.size() > crash_output_size &&
                   snapshot.console_output.substr(crash_output_size)
                           .find("cyclic offset") != std::string::npos;
          })) {
    std::fputs(l10n::text(l10n::Key::HeadlessContextCrashEvidenceMissing),
               stderr);
    return 94;
  }

  std::printf(l10n::text(l10n::Key::HeadlessStopIntelligenceSummary),
              current->branch.taken
                  ? l10n::text(l10n::Key::HeadlessBranchTaken)
                  : l10n::text(l10n::Key::HeadlessBranchNotTaken),
              crash->crash.signal_name.c_str(),
              crash->crash.cyclic_matches.size(), crash->stop_history.size());
  engine.terminate();
  return 0;
}

} // namespace mydbg::app
