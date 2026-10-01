#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
} // namespace debugger

namespace mydbg::app {

struct MemoryState;

struct DebuggerMemoryPointer {
  std::size_t pointer_width{};
  bool full_pointer{};
  bool known_byte_order{};
  std::optional<std::uint64_t> pointer;
};

std::optional<std::uint64_t>
debugger_memory_visible_hint_end(const debugger::SessionSnapshot &snapshot,
                                 const MemoryState &state);

bool debugger_sync_memory_selection(const debugger::SessionSnapshot &snapshot,
                                    MemoryState &state);

void debugger_sync_memory_editor(const debugger::SessionSnapshot &snapshot,
                                 MemoryState &state, bool dump_changed,
                                 std::size_t editable_count);

void debugger_patch_memory_byte(const debugger::SessionSnapshot &snapshot,
                                debugger::LldbEngine &engine,
                                MemoryState &state, std::size_t byte_offset,
                                std::uint64_t byte_address);

bool debugger_memory_address_is_code(const debugger::SessionSnapshot &snapshot,
                                     std::uint64_t address);

std::size_t debugger_memory_selection_start(const MemoryState &state);

std::size_t debugger_memory_selection_end(const MemoryState &state);

bool debugger_memory_has_selection(const debugger::SessionSnapshot &snapshot,
                                   const MemoryState &state);

std::span<const std::uint8_t>
debugger_memory_selected_bytes(const debugger::SessionSnapshot &snapshot,
                               const MemoryState &state);

void debugger_select_memory_byte(const debugger::SessionSnapshot &snapshot,
                                 MemoryState &state, std::size_t offset,
                                 bool extend, bool editing);

void debugger_select_memory_context(const debugger::SessionSnapshot &snapshot,
                                    MemoryState &state, std::size_t offset);

bool debugger_memory_byte_is_patched(const debugger::SessionSnapshot &snapshot,
                                     std::uint64_t byte_address);

DebuggerMemoryPointer
debugger_memory_pointer(const debugger::SessionSnapshot &snapshot,
                        std::size_t first);

} // namespace mydbg::app
