#pragma once

#include "backend/decompiler/DecompilerEngine.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace mydbg::app {

enum class DecompilerDialog {
  None,
  Rename,
  SetType,
};

struct DecompilerTarget {
  debugger::DecompilerSymbolKind kind{debugger::DecompilerSymbolKind::None};
  std::string name;
  std::string text;
  std::uint64_t reference_file_address{};
  bool has_reference_file_address{};
  std::uint64_t cursor_file_address{};
  bool has_cursor_file_address{};
};

struct DecompilerState {
  std::optional<DecompilerTarget> target;
  std::optional<DecompilerTarget> context_target;
  std::optional<std::uint64_t> context_load_address;
  std::optional<std::size_t> selection_anchor;
  std::optional<std::size_t> selection_start;
  std::optional<std::size_t> selection_end;
  std::optional<std::size_t> keyboard_line;
  std::optional<std::size_t> keyboard_span;
  std::optional<std::uint64_t> keyboard_function;
  std::uint64_t keyboard_cursor{};
  std::uint64_t target_serial{};
  DecompilerDialog dialog{DecompilerDialog::None};
  std::array<char, 256> name_text{};
  std::array<char, 1024> type_text{};
  std::string message;
  std::uint64_t scroll_selection{};
};

} // namespace mydbg::app
