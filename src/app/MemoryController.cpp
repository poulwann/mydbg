#include "app/MemoryController.h"
#include "app/AppActions.h"
#include "app/MemoryState.h"
#include "backend/lldb/LldbEngine.h"
#include "localization/Localization.h"

#include <algorithm>
#include <cstdio>

namespace mydbg::app {

std::optional<std::uint64_t>
debugger_memory_visible_hint_end(const debugger::SessionSnapshot &snapshot,
                                 const MemoryState &state) {
  if (state.type_hints.empty() || snapshot.memory.empty()) {
    return std::nullopt;
  }
  const std::uint64_t dump_end =
      snapshot.memory_base + static_cast<std::uint64_t>(snapshot.memory.size());
  bool any_visible = false;
  for (const MemoryTypeHint &hint : state.type_hints) {
    any_visible = any_visible || (hint.address >= snapshot.memory_base &&
                                  hint.address < dump_end);
  }
  return any_visible ? std::optional{dump_end} : std::nullopt;
}

bool debugger_sync_memory_selection(const debugger::SessionSnapshot &snapshot,
                                    MemoryState &state) {
  const bool dump_changed = state.selection_generation != snapshot.generation ||
                            state.selection_base != snapshot.memory_base ||
                            state.selection_size != snapshot.memory.size();
  if (dump_changed) {
    state.selection_generation = snapshot.generation;
    state.selection_base = snapshot.memory_base;
    state.selection_size = snapshot.memory.size();
    state.selection_anchor.reset();
    state.selection_end.reset();
    state.selection_dragging = false;
    state.edit_focus.reset();
    state.edit_error.clear();
  }
  return dump_changed;
}

void debugger_sync_memory_editor(const debugger::SessionSnapshot &snapshot,
                                 MemoryState &state, bool dump_changed,
                                 std::size_t editable_count) {
  if (dump_changed || state.edit_base != snapshot.memory_base ||
      state.edit_source != snapshot.memory) {
    state.edit_base = snapshot.memory_base;
    state.edit_source = snapshot.memory;
    state.edit_focus.reset();
    for (auto &byte : state.edit_bytes) {
      byte.fill('\0');
    }
    for (std::size_t index = 0; index < editable_count; ++index) {
      std::snprintf(state.edit_bytes[index].data(),
                    state.edit_bytes[index].size(), "%02X",
                    static_cast<unsigned int>(snapshot.memory[index]));
    }
  }
}

void debugger_patch_memory_byte(const debugger::SessionSnapshot &snapshot,
                                debugger::LldbEngine &engine,
                                MemoryState &state, std::size_t byte_offset,
                                std::uint64_t byte_address) {
  const auto replacement =
      parse_hex_byte_text(state.edit_bytes[byte_offset].data());
  if (!replacement || replacement->size() != 1) {
    state.edit_error = l10n::text(l10n::Key::GuiPanelsHexByteRequired);
    std::snprintf(state.edit_bytes[byte_offset].data(),
                  state.edit_bytes[byte_offset].size(), "%02X",
                  static_cast<unsigned int>(snapshot.memory[byte_offset]));
  } else {
    state.edit_error.clear();
    if (replacement->front() != snapshot.memory[byte_offset]) {
      engine.execute_command("patch " + address_specification(byte_address) +
                             " " + bytes_as_hex(*replacement));
    }
  }
}

bool debugger_memory_address_is_code(const debugger::SessionSnapshot &snapshot,
                                     std::uint64_t address) {
  return std::any_of(snapshot.memory_regions.begin(),
                     snapshot.memory_regions.end(), [&](const auto &region) {
                       return region.executable && address >= region.start &&
                              address < region.end;
                     });
}

std::size_t debugger_memory_selection_start(const MemoryState &state) {
  return std::min(*state.selection_anchor, *state.selection_end);
}

std::size_t debugger_memory_selection_end(const MemoryState &state) {
  return std::max(*state.selection_anchor, *state.selection_end);
}

bool debugger_memory_has_selection(const debugger::SessionSnapshot &snapshot,
                                   const MemoryState &state) {
  return state.selection_anchor && state.selection_end &&
         debugger_memory_selection_end(state) < snapshot.memory.size();
}

std::span<const std::uint8_t>
debugger_memory_selected_bytes(const debugger::SessionSnapshot &snapshot,
                               const MemoryState &state) {
  return std::span<const std::uint8_t>{snapshot.memory}.subspan(
      debugger_memory_selection_start(state),
      debugger_memory_selection_end(state) -
          debugger_memory_selection_start(state) + 1);
}

void debugger_select_memory_byte(const debugger::SessionSnapshot &snapshot,
                                 MemoryState &state, std::size_t offset,
                                 bool extend, bool editing) {
  if (!extend || !debugger_memory_has_selection(snapshot, state)) {
    state.selection_anchor = offset;
  }
  state.selection_end = offset;
  state.selection_dragging = !editing;
}

void debugger_select_memory_context(const debugger::SessionSnapshot &snapshot,
                                    MemoryState &state, std::size_t offset) {
  if (!debugger_memory_has_selection(snapshot, state) ||
      offset < debugger_memory_selection_start(state) ||
      offset > debugger_memory_selection_end(state)) {
    state.selection_anchor = offset;
    state.selection_end = offset;
  }
  state.selection_dragging = false;
}

bool debugger_memory_byte_is_patched(const debugger::SessionSnapshot &snapshot,
                                     std::uint64_t byte_address) {
  return std::any_of(snapshot.patches.begin(), snapshot.patches.end(),
                     [byte_address](const debugger::PatchInfo &patch) {
                       return byte_address >= patch.address &&
                              byte_address - patch.address <
                                  patch.replacement.size();
                     });
}

DebuggerMemoryPointer
debugger_memory_pointer(const debugger::SessionSnapshot &snapshot,
                        std::size_t first) {
  const std::size_t pointer_width = snapshot.address_byte_size;
  const bool full_pointer = (pointer_width == 4 || pointer_width == 8) &&
                            pointer_width <= snapshot.memory.size() - first;
  const bool known_byte_order =
      snapshot.byte_order == "little" || snapshot.byte_order == "big";
  const auto pointer = full_pointer && known_byte_order
                           ? pointer_at(snapshot, first)
                           : std::nullopt;
  return {pointer_width, full_pointer, known_byte_order, pointer};
}

} // namespace mydbg::app
