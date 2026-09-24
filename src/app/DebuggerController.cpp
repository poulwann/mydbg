#include "app/DebuggerController.h"
#include "app/AppActions.h"
#include "app/AppState.h"
#include "backend/conditions/BreakpointCondition.h"
#include "localization/Localization.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <limits>
#include <utility>

namespace mydbg::app {

std::string_view trim_view(std::string_view text) {
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.front())) != 0) {
    text.remove_prefix(1);
  }
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.back())) != 0) {
    text.remove_suffix(1);
  }
  return text;
}

void debugger_request_comment_editor(const debugger::SessionSnapshot &snapshot,
                                     UiState &ui, std::uint64_t address,
                                     std::string_view text) {
  ui.comment_address = address;
  ui.comment_generation = snapshot.generation;
  ui.comment_session = snapshot.session;
  const auto size = std::min(text.size(), ui.comment_text.size() - 1);
  if (size != 0)
    std::memcpy(ui.comment_text.data(), text.data(), size);
  ui.comment_text[size] = '\0';
  ui.comment_editor_requested = true;
  ui.comment_write = {};
  ui.comment_error.clear();
}

DebuggerSessionInput debugger_sync_session_input(UiState &ui) {
  std::optional<std::string> selected_executable;
  DebuggerSessionInput input;
  {
    const std::lock_guard lock{ui.file_dialog_mutex};
    selected_executable = std::move(ui.selected_executable);
    ui.selected_executable.reset();
    input.file_dialog_error = ui.file_dialog_error;
    input.file_dialog_open = ui.file_dialog_open;
  }
  if (selected_executable) {
    std::snprintf(ui.executable_path.data(), ui.executable_path.size(), "%s",
                  selected_executable->c_str());
  }
  if (!ui.remote_endpoint_initialized) {
    std::snprintf(ui.remote_endpoint.data(), ui.remote_endpoint.size(), "%s",
                  "connect://127.0.0.1:1234");
    ui.remote_endpoint_initialized = true;
  }
  return input;
}

const debugger::StopHistoryEntry *
debugger_selected_history(const debugger::SessionSnapshot &snapshot,
                          const UiState &ui) {
  const auto selected = std::find_if(
      snapshot.stop_history.begin(), snapshot.stop_history.end(),
      [&ui](const debugger::StopHistoryEntry &entry) {
        return ui.selected_history_generation == entry.generation &&
               ui.selected_history_stop == entry.stop_revision;
      });
  return selected != snapshot.stop_history.end() ? &*selected : nullptr;
}

bool debugger_validate_comment(const debugger::SessionSnapshot &snapshot,
                               UiState &ui, bool control_lease) {
  const bool valid =
      ui.comment_address && ui.comment_generation == snapshot.generation &&
      ui.comment_session == snapshot.session && !ui.session_clear.valid() &&
      snapshot.state == debugger::SessionState::Stopped && !control_lease;
  if (!valid) {
    ui.comment_address.reset();
    ui.comment_write = {};
  }
  return valid;
}

bool debugger_complete_comment(UiState &ui) {
  if (ui.comment_write.valid() &&
      ui.comment_write.wait_for(std::chrono::milliseconds{0})) {
    const auto result = ui.comment_write.get();
    ui.comment_write = {};
    if (result.success) {
      ui.comment_address.reset();
      return true;
    }
    ui.comment_error = result.message;
  }
  return false;
}

void debugger_sync_disassembly_mode(const debugger::SessionSnapshot &snapshot,
                                    debugger::LldbEngine &engine, UiState &ui) {
  if (ui.disassembly_graph_enabled != ui.disassembly_graph_view) {
    const bool cursor_in_linear_view =
        std::any_of(snapshot.instructions.begin(), snapshot.instructions.end(),
                    [&ui](const debugger::InstructionRow &instruction) {
                      return instruction.address == ui.disassembly_cursor;
                    });
    if (snapshot.state == debugger::SessionState::Stopped &&
        ui.disassembly_cursor != 0 &&
        (ui.disassembly_graph_view || !cursor_in_linear_view)) {
      follow_disassembly(engine, ui, ui.disassembly_cursor);
    }
    engine.set_disassembly_graph_enabled(ui.disassembly_graph_view);
    ui.disassembly_graph_enabled = ui.disassembly_graph_view;
  }
}

std::vector<debugger::InstructionRow>::const_iterator
debugger_disassembly_cursor(const debugger::SessionSnapshot &snapshot,
                            const UiState &ui) {
  return std::find_if(
      snapshot.instructions.begin(), snapshot.instructions.end(),
      [&ui](const auto &row) { return row.address == ui.disassembly_cursor; });
}

std::vector<debugger::InstructionRow>::const_iterator
debugger_move_disassembly_cursor(
    const debugger::SessionSnapshot &snapshot, UiState &ui,
    std::vector<debugger::InstructionRow>::const_iterator cursor, bool up,
    bool down) {
  if (cursor == snapshot.instructions.end()) {
    cursor = snapshot.instructions.begin();
  } else if (up && cursor != snapshot.instructions.begin()) {
    --cursor;
  } else if (down && cursor + 1 != snapshot.instructions.end()) {
    ++cursor;
  }
  ui.disassembly_cursor = cursor->address;
  return cursor;
}

void debugger_follow_memory_region(debugger::LldbEngine &engine, UiState &ui,
                                   const debugger::MemoryRegionInfo &region) {
  ui.memory_map_address = region.start;
  if (region.executable) {
    follow_disassembly(engine, ui, region.start);
  } else if (region.readable) {
    follow_memory(engine, ui, region.start);
  }
}

std::optional<std::uint64_t>
debugger_memory_visible_hint_end(const debugger::SessionSnapshot &snapshot,
                                 const UiState &ui) {
  if (ui.memory_type_hints.empty() || snapshot.memory.empty()) {
    return std::nullopt;
  }
  const std::uint64_t dump_end =
      snapshot.memory_base + static_cast<std::uint64_t>(snapshot.memory.size());
  bool any_visible = false;
  for (const MemoryTypeHint &hint : ui.memory_type_hints) {
    any_visible = any_visible || (hint.address >= snapshot.memory_base &&
                                  hint.address < dump_end);
  }
  return any_visible ? std::optional{dump_end} : std::nullopt;
}

void debugger_complete_register_write(const debugger::SessionSnapshot &snapshot,
                                      UiState &ui) {
  if (ui.register_write.valid() &&
      ui.register_write.wait_for(std::chrono::milliseconds{0})) {
    const auto result = ui.register_write.get();
    if (snapshot.revision >= result.snapshot_revision) {
      ui.register_write = {};
      ui.register_edit_revision = snapshot.revision;
      if (result.success) {
        ui.register_edit_name.clear();
        ui.register_edit_error.clear();
      } else {
        ui.register_edit_error = l10n::format(
            l10n::Key::GuiPanelsRegisterWriteError,
            ui.register_write_name.c_str(), result.message.c_str());
        ui.register_edit_focus = true;
      }
    }
  }
}

void debugger_begin_register_edit(const debugger::SessionSnapshot &snapshot,
                                  UiState &ui,
                                  const debugger::RegisterValue &value) {
  ui.register_edit_name = value.name;
  std::snprintf(ui.register_edit_text.data(), ui.register_edit_text.size(),
                "%s", value.value.c_str());
  ui.register_edit_revision = snapshot.revision;
  ui.register_edit_focus = true;
  ui.register_edit_error.clear();
}

void debugger_write_register(debugger::LldbEngine &engine, UiState &ui,
                             const debugger::RegisterValue &value,
                             std::string text) {
  ui.register_write_name = value.name;
  ui.register_edit_error.clear();
  ui.register_write = engine.write_register(value.name, std::move(text));
}

void debugger_clear_register(debugger::LldbEngine &engine, UiState &ui,
                             const debugger::RegisterValue &value) {
  ui.register_edit_name.clear();
  std::string zero = "0";
  if (value.value.starts_with("{")) {
    zero = "{";
    for (std::uint64_t byte = 0; byte < value.byte_size; ++byte) {
      zero += " 0x00";
    }
    zero += " }";
  }
  debugger_write_register(engine, ui, value, std::move(zero));
}

bool debugger_register_is_integer(const debugger::RegisterValue &value) {
  return value.has_numeric_value && value.byte_size > 0 &&
         value.byte_size <= sizeof(std::uint64_t) &&
         parse_value(value.value).has_value();
}

std::uint64_t debugger_register_mask(const debugger::RegisterValue &value,
                                     bool integer) {
  return integer && value.byte_size < sizeof(std::uint64_t)
             ? (std::uint64_t{1} << (value.byte_size * 8)) - 1
             : std::numeric_limits<std::uint64_t>::max();
}

bool debugger_apply_condition(debugger::LldbEngine &engine, UiState &ui,
                              bool creating, std::uint32_t breakpoint_id) {
  const std::string_view source{ui.breakpoint_condition.data()};
  if (source.empty() && !creating) {
    engine.set_breakpoint_script(breakpoint_id, {});
    return true;
  }
  const debugger::conditions::CompileResult result =
      debugger::conditions::compile(source);
  if (!result) {
    ui.breakpoint_condition_error = result.error;
    return false;
  }
  if (creating) {
    engine.set_conditional_breakpoint(
        address_specification(*ui.creating_conditional_breakpoint),
        std::string{source});
  } else {
    engine.set_breakpoint_script(breakpoint_id, std::string{source});
  }
  return true;
}

bool debugger_sync_memory_selection(const debugger::SessionSnapshot &snapshot,
                                    UiState &ui) {
  const bool dump_changed =
      ui.memory_selection_generation != snapshot.generation ||
      ui.memory_selection_base != snapshot.memory_base ||
      ui.memory_selection_size != snapshot.memory.size();
  if (dump_changed) {
    ui.memory_selection_generation = snapshot.generation;
    ui.memory_selection_base = snapshot.memory_base;
    ui.memory_selection_size = snapshot.memory.size();
    ui.memory_selection_anchor.reset();
    ui.memory_selection_end.reset();
    ui.memory_selection_dragging = false;
    ui.memory_edit_focus.reset();
    ui.memory_edit_error.clear();
  }
  return dump_changed;
}

void debugger_sync_memory_editor(const debugger::SessionSnapshot &snapshot,
                                 UiState &ui, bool dump_changed,
                                 std::size_t editable_count) {
  if (dump_changed || ui.memory_edit_base != snapshot.memory_base ||
      ui.memory_edit_source != snapshot.memory) {
    ui.memory_edit_base = snapshot.memory_base;
    ui.memory_edit_source = snapshot.memory;
    ui.memory_edit_focus.reset();
    for (auto &byte : ui.memory_edit_bytes) {
      byte.fill('\0');
    }
    for (std::size_t index = 0; index < editable_count; ++index) {
      std::snprintf(ui.memory_edit_bytes[index].data(),
                    ui.memory_edit_bytes[index].size(), "%02X",
                    static_cast<unsigned int>(snapshot.memory[index]));
    }
  }
}

void debugger_patch_memory_byte(const debugger::SessionSnapshot &snapshot,
                                debugger::LldbEngine &engine, UiState &ui,
                                std::size_t byte_offset,
                                std::uint64_t byte_address) {
  const auto replacement =
      parse_hex_byte_text(ui.memory_edit_bytes[byte_offset].data());
  if (!replacement || replacement->size() != 1) {
    ui.memory_edit_error = l10n::text(l10n::Key::GuiPanelsHexByteRequired);
    std::snprintf(ui.memory_edit_bytes[byte_offset].data(),
                  ui.memory_edit_bytes[byte_offset].size(), "%02X",
                  static_cast<unsigned int>(snapshot.memory[byte_offset]));
  } else {
    ui.memory_edit_error.clear();
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

std::size_t debugger_memory_selection_start(const UiState &ui) {
  return std::min(*ui.memory_selection_anchor, *ui.memory_selection_end);
}

std::size_t debugger_memory_selection_end(const UiState &ui) {
  return std::max(*ui.memory_selection_anchor, *ui.memory_selection_end);
}

bool debugger_memory_has_selection(const debugger::SessionSnapshot &snapshot,
                                   const UiState &ui) {
  return ui.memory_selection_anchor && ui.memory_selection_end &&
         debugger_memory_selection_end(ui) < snapshot.memory.size();
}

std::span<const std::uint8_t>
debugger_memory_selected_bytes(const debugger::SessionSnapshot &snapshot,
                               const UiState &ui) {
  return std::span<const std::uint8_t>{snapshot.memory}.subspan(
      debugger_memory_selection_start(ui),
      debugger_memory_selection_end(ui) - debugger_memory_selection_start(ui) +
          1);
}

void debugger_select_memory_byte(const debugger::SessionSnapshot &snapshot,
                                 UiState &ui, std::size_t offset, bool extend,
                                 bool editing) {
  if (!extend || !debugger_memory_has_selection(snapshot, ui)) {
    ui.memory_selection_anchor = offset;
  }
  ui.memory_selection_end = offset;
  ui.memory_selection_dragging = !editing;
}

void debugger_select_memory_context(const debugger::SessionSnapshot &snapshot,
                                    UiState &ui, std::size_t offset) {
  if (!debugger_memory_has_selection(snapshot, ui) ||
      offset < debugger_memory_selection_start(ui) ||
      offset > debugger_memory_selection_end(ui)) {
    ui.memory_selection_anchor = offset;
    ui.memory_selection_end = offset;
  }
  ui.memory_selection_dragging = false;
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
