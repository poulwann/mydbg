#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace mydbg::app {

struct DisassemblyGraphView;
struct DisassemblyTextCache;

struct NavigationLocation {
  std::uint64_t address{};
  std::optional<std::uint64_t> decompiler_function{};
  std::optional<std::size_t> decompiler_line{};
  std::optional<std::size_t> decompiler_span{};
};

struct NavigationState {
  std::uint64_t disassembly_cursor{};
  std::uint64_t cursor_generation{};
  std::uint64_t cursor_stop_revision{};
  std::uint64_t disassembly_scroll_generation{};
  std::uint64_t disassembly_scroll_stop_revision{};
  std::optional<std::uint64_t> disassembly_scroll_target;
  bool disassembly_graph_view{};
  std::optional<bool> disassembly_graph_enabled;
  std::shared_ptr<DisassemblyGraphView> disassembly_graph_state;
  std::shared_ptr<DisassemblyTextCache> disassembly_text_cache;
  std::array<NavigationLocation, 256> history{};
  std::optional<NavigationLocation> source_restore;
  std::size_t history_size{};
  std::size_t history_index{};
  bool follow_requested{};
  int dispatch_frame{-1};
  bool control_locked{};
  bool dialog_requested{};
  bool dialog_decompiler_view{};
  bool dialog_open{};
  std::uint64_t dialog_generation{};
  std::array<char, 64> address{};
  std::string address_error;
  std::optional<std::uint64_t> memory_map_address;
  bool scroll_memory_map_to_address{};
};

} // namespace mydbg::app
