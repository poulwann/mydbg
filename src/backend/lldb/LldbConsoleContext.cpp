#include "backend/lldb/LldbEngineInternal.h"
#include "backend/lldb/LldbNativeCommands.h"
#include "localization/Localization.h"

namespace debugger::lldb_detail {

const char *NativeCommandStatus::error_response(const char *message) {
  failed_ = true;
  return message;
}

std::string NativeCommandStatus::error_detail(const std::string &message) {
  failed_ = true;
  return l10n::format(l10n::Key::EngineErrorDetail, message.c_str());
}

std::string
render_console_context(const SessionSnapshot &state,
                       const std::vector<std::string> &context_sections,
                       std::string_view requested_section) {
  const std::vector<std::string> sections =
      requested_section.empty()
          ? context_sections
          : std::vector<std::string>{lowercase(trim(requested_section))};
  const auto enabled = [&sections](std::string_view section) {
    return std::find(sections.begin(), sections.end(), section) !=
           sections.end();
  };
  const auto write_pointer_chain =
      [](std::ostringstream &stream,
         const std::vector<PointerChainEntry> &chain) {
        for (const PointerChainEntry &entry : chain) {
          stream << " -> ";
          if (!entry.error.empty()) {
            stream << '<' << entry.error << '>';
            break;
          }
          stream << "0x" << std::hex << entry.value;
          if (!entry.symbol.empty()) {
            stream << " (" << entry.symbol << ')';
          } else if (!entry.mapping.empty()) {
            stream << " (" << entry.mapping << ')';
          }
        }
      };

  std::ostringstream output;
  if (enabled("regs")) {
    output << l10n::text(l10n::Key::EngineRegisters);
    for (const RegisterValue &value : state.registers) {
      output << value.name << '=' << value.value;
      if (value.changed) {
        output << l10n::format(l10n::Key::EnginePreviousRegisterValue,
                               value.previous_value.c_str());
      }
      write_pointer_chain(output, value.pointer_chain);
      output << '\n';
    }
    output << '\n';
  }
  if (enabled("disasm")) {
    output << l10n::text(l10n::Key::EngineDisassembly);
    for (const InstructionRow &instruction : state.instructions) {
      if (instruction.address + 64 < state.pc ||
          instruction.address > state.pc + 64) {
        continue;
      }
      output << (instruction.address == state.pc ? "=> " : "   ") << "0x"
             << std::hex << instruction.address << ' ' << instruction.mnemonic
             << ' ' << instruction.operands << '\n';
    }
  }
  if (enabled("insight") || enabled("operands") || enabled("args")) {
    output << l10n::text(l10n::Key::EngineInstructionInsight);
    const auto current =
        std::find_if(state.instructions.begin(), state.instructions.end(),
                     [&state](const InstructionRow &instruction) {
                       return instruction.address == state.pc;
                     });
    if (current == state.instructions.end()) {
      output << l10n::text(
          l10n::Key::EngineUnavailableCurrentInstructionWasNotCaptured);
    } else {
      for (const ResolvedOperandInfo &operand : current->resolved_operands) {
        output << operand_role_display(operand.role) << ' '
               << operand.expression;
        if (!operand.error.empty()) {
          output << " = <" << operand.error << ">\n";
          continue;
        }
        if (operand.has_value) {
          output << " = 0x" << std::hex << operand.value;
          write_pointer_chain(output, operand.pointer_chain);
        }
        output << '\n';
      }
      if (current->branch.conditional) {
        output << l10n::text(l10n::Key::EngineBranch);
        if (current->branch.available) {
          output << (current->branch.taken
                         ? l10n::text(l10n::Key::EngineTAKEN)
                         : l10n::text(l10n::Key::EngineNOTTAKEN));
        } else {
          output << l10n::text(l10n::Key::EngineUNKNOWN);
        }
        output << " (" << current->branch.explanation << ") -> 0x" << std::hex
               << (current->branch.taken ? current->branch.taken_target
                                         : current->branch.fallthrough_target)
               << '\n';
      }
      if (!current->arguments.empty()) {
        output << (current->flow_kind == InstructionFlowKind::Syscall
                       ? l10n::text(l10n::Key::EngineSyscallArguments)
                       : l10n::text(l10n::Key::EngineCallArguments));
        for (const AbiArgumentInfo &argument : current->arguments) {
          output << "  " << argument.name << " = ";
          if (!argument.error.empty()) {
            output << '<' << argument.error << '>';
          } else {
            output << "0x" << std::hex << argument.value;
            write_pointer_chain(output, argument.pointer_chain);
          }
          output << '\n';
        }
      }
    }
  }
  if (enabled("stack")) {
    output << l10n::text(l10n::Key::EngineStack);
    for (const StackEntry &entry : state.stack) {
      output << "0x" << std::hex << entry.address << "  0x" << entry.value;
      if (!entry.symbol.empty()) {
        output << "  " << entry.symbol;
      }
      write_pointer_chain(output, entry.pointer_chain);
      output << '\n';
    }
  }
  if (enabled("backtrace")) {
    output << l10n::text(l10n::Key::EngineBacktrace);
    for (const ThreadInfo &thread : state.threads) {
      if (!thread.selected) {
        continue;
      }
      for (const StackFrameInfo &frame : thread.frames) {
        output << '#' << std::dec << frame.index << " 0x" << std::hex
               << frame.pc << ' ' << frame.function << '\n';
      }
    }
  }
  if (enabled("threads")) {
    output << l10n::text(l10n::Key::EngineThreads);
    for (const ThreadInfo &thread : state.threads) {
      output << (thread.selected ? "* " : "  ") << std::dec << thread.index
             << " tid=0x" << std::hex << thread.id << ' ' << thread.name << ' '
             << thread.stop_reason << '\n';
    }
  }
  if (enabled("expressions") || enabled("watches")) {
    output << l10n::text(l10n::Key::EngineExpressions);
    for (const WatchInfo &watch : state.watches) {
      output << watch.expression << " = "
             << (watch.error.empty() ? watch.value : watch.error) << '\n';
    }
  }
  if (enabled("history")) {
    output << l10n::text(l10n::Key::EngineStopHistory);
    for (const StopHistoryEntry &entry : state.stop_history) {
      output << l10n::format(l10n::Key::EngineStopHistoryEntry,
                             entry.generation, entry.stop_revision,
                             entry.thread_id, entry.pc, entry.sp,
                             entry.stop_reason.c_str());
    }
  }
  if (enabled("crash")) {
    output << l10n::text(l10n::Key::EngineCrash);
    if (!state.crash.crashed) {
      output << l10n::text(l10n::Key::EngineNotCrashed);
    } else {
      output << state.crash.summary << '\n'
             << l10n::text(l10n::Key::EngineStackExecutable)
             << (state.crash.stack_executable ? l10n::text(l10n::Key::EngineYes)
                                              : l10n::text(l10n::Key::EngineNo))
             << '\n';
      for (const CyclicMatch &match : state.crash.cyclic_matches) {
        output << cyclic_source_display(match.source);
        if (match.has_address) {
          output << " @ 0x" << std::hex << match.address;
        }
        output << l10n::text(l10n::Key::EngineCyclicOffset) << std::dec
               << match.offset << " (" << match.bytes << ")\n";
      }
    }
  }
  if (enabled("ghidra")) {
    output << l10n::text(l10n::Key::EngineGhidra)
           << l10n::text(l10n::Key::EngineSeeTheSynchronizedDecompilerPanel);
  }
  return output.str();
}

} // namespace debugger::lldb_detail
