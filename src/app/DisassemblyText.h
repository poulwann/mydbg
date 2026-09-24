#pragma once

#include "backend/lldb/LldbEngine.h"

#include <imgui.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mydbg::app {

enum class DisassemblyTokenKind {
  Plain,
  Mnemonic,
  ControlFlow,
  Register,
  Number,
  Punctuation,
  Symbol,
  Type,
  String,
  Comment,
  Runtime,
};

struct DisassemblyToken {
  std::size_t begin{};
  std::size_t end{};
  DisassemblyTokenKind kind{};
  std::optional<std::uint64_t> target;
};

struct DisassemblyTextRun {
  DisassemblyToken token;
  ImVec2 position;
};

struct DisassemblyText {
  std::string text;
  std::vector<DisassemblyToken> tokens;
  std::vector<DisassemblyTextRun> runs;
  ImVec2 size;
};

struct DisassemblyPresentation {
  DisassemblyText instruction;
  DisassemblyText annotation;
  std::string bytes;
};

DisassemblyPresentation
make_disassembly_presentation(const debugger::InstructionRow &instruction,
                              std::string_view architecture);
bool navigable_address(const debugger::SessionSnapshot &snapshot,
                       std::uint64_t address);
std::optional<std::uint64_t>
disassembly_navigation_target(const debugger::SessionSnapshot &snapshot,
                              const debugger::InstructionRow &instruction,
                              const DisassemblyPresentation &presentation);

} // namespace mydbg::app
