#include "app/DebuggerController.h"
#include "app/AppActions.h"
#include "app/AppState.h"
#include "backend/conditions/BreakpointCondition.h"
#include "backend/lldb/LldbEngine.h"
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
                                     CommentState &state, std::uint64_t address,
                                     std::string_view text) {
  state.address = address;
  state.generation = snapshot.generation;
  state.session = snapshot.session;
  const auto size = std::min(text.size(), state.text.size() - 1);
  if (size != 0)
    std::memcpy(state.text.data(), text.data(), size);
  state.text[size] = '\0';
  state.editor_requested = true;
  state.write = {};
  state.error.clear();
}

DebuggerSessionInput debugger_sync_session_input(SessionInputState &state,
                                                 FileDialogState &files) {
  std::optional<std::string> selected_executable;
  DebuggerSessionInput input;
  {
    const std::lock_guard lock{files.mutex};
    selected_executable = std::move(files.selected_executable);
    files.selected_executable.reset();
    input.file_dialog_error = files.error;
    input.file_dialog_open = files.open;
  }
  if (selected_executable) {
    std::snprintf(state.executable_path.data(), state.executable_path.size(),
                  "%s", selected_executable->c_str());
  }
  if (!state.remote_endpoint_initialized) {
    std::snprintf(state.remote_endpoint.data(), state.remote_endpoint.size(),
                  "%s", "connect://127.0.0.1:1234");
    state.remote_endpoint_initialized = true;
  }
  return input;
}

const debugger::StopHistoryEntry *
debugger_selected_history(const debugger::SessionSnapshot &snapshot,
                          const HistoryState &state) {
  const auto selected =
      std::find_if(snapshot.stop_history.begin(), snapshot.stop_history.end(),
                   [&state](const debugger::StopHistoryEntry &entry) {
                     return state.generation == entry.generation &&
                            state.stop == entry.stop_revision;
                   });
  return selected != snapshot.stop_history.end() ? &*selected : nullptr;
}

bool debugger_validate_comment(const debugger::SessionSnapshot &snapshot,
                               CommentState &state,
                               const SessionInputState &session,
                               bool control_lease) {
  const bool valid =
      state.address && state.generation == snapshot.generation &&
      state.session == snapshot.session && !session.clear.valid() &&
      snapshot.state == debugger::SessionState::Stopped && !control_lease;
  if (!valid) {
    state.address.reset();
    state.write = {};
  }
  return valid;
}

bool debugger_complete_comment(CommentState &state) {
  if (state.write.valid() &&
      state.write.wait_for(std::chrono::milliseconds{0})) {
    const auto result = state.write.get();
    state.write = {};
    if (result.success) {
      state.address.reset();
      return true;
    }
    state.error = result.message;
  }
  return false;
}

void debugger_sync_disassembly_mode(const debugger::SessionSnapshot &snapshot,
                                    debugger::LldbEngine &engine, UiState &ui) {
  if (ui.navigation.disassembly_graph_enabled !=
      ui.navigation.disassembly_graph_view) {
    const bool cursor_in_linear_view = std::any_of(
        snapshot.instructions.begin(), snapshot.instructions.end(),
        [&ui](const debugger::InstructionRow &instruction) {
          return instruction.address == ui.navigation.disassembly_cursor;
        });
    if (snapshot.state == debugger::SessionState::Stopped &&
        ui.navigation.disassembly_cursor != 0 &&
        (ui.navigation.disassembly_graph_view || !cursor_in_linear_view)) {
      follow_disassembly(engine, ui, ui.navigation.disassembly_cursor);
    }
    engine.set_disassembly_graph_enabled(ui.navigation.disassembly_graph_view);
    ui.navigation.disassembly_graph_enabled =
        ui.navigation.disassembly_graph_view;
  }
}

std::vector<debugger::InstructionRow>::const_iterator
debugger_disassembly_cursor(const debugger::SessionSnapshot &snapshot,
                            const UiState &ui) {
  return std::find_if(snapshot.instructions.begin(),
                      snapshot.instructions.end(), [&ui](const auto &row) {
                        return row.address == ui.navigation.disassembly_cursor;
                      });
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
  ui.navigation.disassembly_cursor = cursor->address;
  return cursor;
}

void debugger_follow_memory_region(debugger::LldbEngine &engine, UiState &ui,
                                   const debugger::MemoryRegionInfo &region) {
  ui.navigation.memory_map_address = region.start;
  if (region.executable) {
    follow_disassembly(engine, ui, region.start);
  } else if (region.readable) {
    follow_memory(engine, ui.memory, region.start);
  }
}

void debugger_complete_register_write(const debugger::SessionSnapshot &snapshot,
                                      RegisterState &state) {
  if (state.write.valid() &&
      state.write.wait_for(std::chrono::milliseconds{0})) {
    const auto result = state.write.get();
    if (snapshot.revision >= result.snapshot_revision) {
      state.write = {};
      state.edit_revision = snapshot.revision;
      if (result.success) {
        state.edit_name.clear();
        state.edit_error.clear();
      } else {
        state.edit_error =
            l10n::format(l10n::Key::GuiPanelsRegisterWriteError,
                         state.write_name.c_str(), result.message.c_str());
        state.edit_focus = true;
      }
    }
  }
}

void debugger_begin_register_edit(const debugger::SessionSnapshot &snapshot,
                                  RegisterState &state,
                                  const debugger::RegisterValue &value) {
  state.edit_name = value.name;
  std::snprintf(state.edit_text.data(), state.edit_text.size(), "%s",
                value.value.c_str());
  state.edit_revision = snapshot.revision;
  state.edit_focus = true;
  state.edit_error.clear();
}

void debugger_write_register(debugger::LldbEngine &engine, RegisterState &state,
                             const debugger::RegisterValue &value,
                             std::string text) {
  state.write_name = value.name;
  state.edit_error.clear();
  state.write = engine.write_register(value.name, std::move(text));
}

void debugger_clear_register(debugger::LldbEngine &engine, RegisterState &state,
                             const debugger::RegisterValue &value) {
  state.edit_name.clear();
  std::string zero = "0";
  if (value.value.starts_with("{")) {
    zero = "{";
    for (std::uint64_t byte = 0; byte < value.byte_size; ++byte) {
      zero += " 0x00";
    }
    zero += " }";
  }
  debugger_write_register(engine, state, value, std::move(zero));
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

bool debugger_apply_condition(debugger::LldbEngine &engine,
                              BreakpointState &state, bool creating,
                              std::uint32_t breakpoint_id) {
  const std::string_view source{state.condition.data()};
  if (source.empty() && !creating) {
    engine.set_breakpoint_script(breakpoint_id, {});
    return true;
  }
  const debugger::conditions::CompileResult result =
      debugger::conditions::compile(source);
  if (!result) {
    state.condition_error = result.error;
    return false;
  }
  if (creating) {
    engine.set_conditional_breakpoint(address_specification(*state.creating),
                                      std::string{source});
  } else {
    engine.set_breakpoint_script(breakpoint_id, std::string{source});
  }
  return true;
}

} // namespace mydbg::app
