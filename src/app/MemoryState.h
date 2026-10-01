#pragma once

#include "app/MemoryData.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace mydbg::app {

struct MemoryTypeHint {
  std::uint64_t address{};
  std::string label;
  std::string type;
  bool string{};
  std::string module_path;
};

struct MemoryState {
  std::array<char, 128> address{};
  bool edit_mode{};
  std::uint64_t edit_base{};
  std::vector<std::uint8_t> edit_source;
  std::array<std::array<char, 3>, 256> edit_bytes{};
  std::optional<std::size_t> edit_focus;
  std::string edit_error;
  std::uint64_t selection_generation{};
  std::uint64_t selection_base{};
  std::size_t selection_size{};
  std::optional<std::size_t> selection_anchor;
  std::optional<std::size_t> selection_end;
  bool selection_dragging{};
  MemoryByteOrder copy_order{MemoryByteOrder::AsStored};
  std::size_t copy_word_size{4};
  std::vector<MemoryTypeHint> type_hints;
  std::uint64_t hints_serial{};
};

} // namespace mydbg::app
