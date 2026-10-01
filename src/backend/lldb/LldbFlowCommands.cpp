#include "backend/lldb/LldbEngineInternal.h"
#include "backend/lldb/LldbNativeCommands.h"
#include "backend/lldb/LldbRemoteArchitecture.h"
#include "localization/Localization.h"

namespace debugger::lldb_detail {

std::string continue_process(lldb::SBTarget &target, lldb::SBProcess &process,
                             SessionSnapshot &state, bool &failed) {
  NativeCommandStatus status{failed};
  if (state.state != SessionState::Stopped || !process.IsValid()) {
    state.error = l10n::text(
        l10n::Key::EngineContinueIsOnlyValidWhileTheProcessIsStopped);
    return status.error_detail(state.error);
  }

  if (is_frameless_qemu_mips_stop(process, state)) {
    const bool at_breakpoint = std::ranges::any_of(
        state.breakpoints, [&state](const BreakpointInfo &breakpoint) {
          return breakpoint.enabled &&
                 std::ranges::find(breakpoint.addresses, state.pc) !=
                     breakpoint.addresses.end();
        });
    if (at_breakpoint) {
      std::string failure;
      if (!step_frameless_qemu_mips_at_breakpoint(target, state, failure)) {
        state.error = std::move(failure);
        return status.error_detail(state.error);
      }
    }
  }

  lldb::SBError continue_error = process.Continue();
  if (continue_error.Fail()) {
    state.error = error_text(continue_error);
    return status.error_detail(state.error);
  }
  state.state = SessionState::Running;
  state.crash = {};
  state.error.clear();
  return std::string{l10n::text(l10n::Key::EngineRunning)};
}

std::string pause_process(lldb::SBProcess &process, SessionSnapshot &state,
                          bool &failed) {
  NativeCommandStatus status{failed};
  if (state.state != SessionState::Running || !process.IsValid()) {
    state.error =
        l10n::text(l10n::Key::EnginePauseIsOnlyValidWhileTheProcessIsRunning);
    return status.error_detail(state.error);
  }
  lldb::SBError stop_error = process.Stop();
  if (stop_error.Fail()) {
    state.error = error_text(stop_error);
    return status.error_detail(state.error);
  }
  state.error.clear();
  return std::string{l10n::text(l10n::Key::EnginePauseRequested)};
}

std::string run_to_address(lldb::addr_t address, lldb::SBProcess &process,
                           SessionSnapshot &state, bool &failed) {
  NativeCommandStatus status{failed};
  if (state.state != SessionState::Stopped || !process.IsValid()) {
    state.error =
        l10n::text(l10n::Key::EngineRunToCursorRequiresAStoppedProcess);
    return status.error_detail(state.error);
  }
  lldb::SBThread thread = process.GetSelectedThread();
  if (!thread.IsValid()) {
    state.error = l10n::text(l10n::Key::EngineNoSelectedThread);
    return status.error_detail(state.error);
  }
  lldb::SBError run_error;
  thread.RunToAddress(address, run_error);
  if (run_error.Fail()) {
    state.error = error_text(run_error);
    return status.error_detail(state.error);
  }
  state.state = SessionState::Running;
  state.crash = {};
  state.error.clear();
  return l10n::format(l10n::Key::EngineRunningToAddress,
                      static_cast<std::uint64_t>(address));
}

std::string terminate_process(lldb::SBProcess &process, SessionSnapshot &state,
                              bool &failed) {
  NativeCommandStatus status{failed};
  if (!process.IsValid() || state.state == SessionState::Exited) {
    state.error = l10n::text(l10n::Key::EngineNoLiveProcessToTerminate);
    return status.error_detail(state.error);
  }
  lldb::SBError kill_error = process.Kill();
  if (kill_error.Fail()) {
    state.error = error_text(kill_error);
    return status.error_detail(state.error);
  }
  state.error.clear();
  return std::string{l10n::text(l10n::Key::EngineProcessTerminated)};
}

std::optional<std::string>
execute_flow_command(std::string_view command, std::string_view arguments,
                     lldb::SBTarget &target, lldb::SBProcess &process,
                     SessionSnapshot &state, bool &failed) {
  NativeCommandStatus status{failed};
  std::string response;
  if (command == "xuntil" || command == "stepuntilasm" ||
      command == "nextcall" || command == "nextproginstr" ||
      command == "nextbranch" || command == "nextjmp" || command == "nextret" ||
      command == "stepret" || command == "nextsyscall" ||
      command == "stepsyscall") {
    const std::vector<std::string> values = split_arguments(arguments);
    std::size_t instruction_limit = 256;
    if ((command == "xuntil" || command == "stepuntilasm") &&
        values.size() > 1) {
      if (const auto parsed = parse_integer(values[1])) {
        instruction_limit = static_cast<std::size_t>(
            std::clamp<std::uint64_t>(*parsed, 1, 4096));
      }
    }
    if ((command == "xuntil" || command == "stepuntilasm") && values.empty()) {
      response =
          l10n::text(l10n::Key::EngineUsageXuntilMnemonicMaxInstructions);
    } else {
      lldb::SBInstructionList instructions = target.ReadInstructions(
          target.ResolveLoadAddress(state.pc),
          static_cast<std::uint32_t>(instruction_limit));
      std::optional<lldb::addr_t> destination;
      for (std::size_t index = 1; index < instructions.GetSize(); ++index) {
        lldb::SBInstruction instruction = instructions.GetInstructionAtIndex(
            static_cast<std::uint32_t>(index));
        const std::string mnemonic =
            lowercase(safe_string(instruction.GetMnemonic(target)));
        bool matches = false;
        if (command == "xuntil" || command == "stepuntilasm") {
          matches = mnemonic.find(lowercase(values[0])) != std::string::npos;
        } else if (command == "nextproginstr") {
          matches = true;
        } else if (command == "nextcall") {
          matches = mnemonic.starts_with("call") || mnemonic == "bl" ||
                    mnemonic == "blr" || mnemonic == "jal" ||
                    mnemonic == "jalr";
        } else if (command == "nextjmp" || command == "nextbranch") {
          matches = mnemonic.starts_with("j") || mnemonic.starts_with("b") ||
                    mnemonic == "cbz" || mnemonic == "cbnz";
        } else if (command == "nextret" || command == "stepret") {
          matches = mnemonic.starts_with("ret") ||
                    (mnemonic == "jr" &&
                     safe_string(instruction.GetOperands(target)).find("ra") !=
                         std::string::npos);
        } else {
          matches = mnemonic == "syscall" || mnemonic == "sysenter" ||
                    mnemonic == "int" || mnemonic == "svc" ||
                    mnemonic == "ecall";
        }
        if (matches) {
          destination = instruction.GetAddress().GetLoadAddress(target);
          break;
        }
      }
      response =
          destination
              ? run_to_address(*destination, process, state, failed)
              : l10n::format(l10n::Key::EngineMatchingInstructionNotFound,
                             instruction_limit);
    }
  } else if (command == "g" || command == "go" || command == "c" ||
             command == "continue") {
    response = continue_process(target, process, state, failed);
  } else if (command == "pause" || command == "breakin") {
    response = pause_process(process, state, failed);
  } else if (command == "t" || command == "step" || command == "p" ||
             command == "next" || command == "ti" || command == "si" ||
             command == "stepi" || command == "pi" || command == "ni" ||
             command == "nexti") {
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      response = status.error_response(
          l10n::text(l10n::Key::EngineErrorSteppingRequiresAStoppedProcess));
    } else {
      lldb::SBThread thread = process.GetSelectedThread();
      if (!thread.IsValid()) {
        response = status.error_response(
            l10n::text(l10n::Key::EngineErrorNoSelectedThread));
      } else {
        lldb::SBError step_error;
        if (command == "t" || command == "step") {
          thread.StepInto();
        } else if (command == "p" || command == "next") {
          thread.StepOver();
        } else {
          const bool step_over =
              command == "pi" || command == "ni" || command == "nexti";
          thread.StepInstruction(step_over, step_error);
        }
        if (step_error.Fail()) {
          response = status.error_detail(error_text(step_error));
        } else {
          state.state = SessionState::Running;
          state.crash = {};
          state.error.clear();
          response = l10n::text(l10n::Key::EngineStepping);
        }
      }
    }
  } else {
    return std::nullopt;
  }
  return response;
}

} // namespace debugger::lldb_detail
