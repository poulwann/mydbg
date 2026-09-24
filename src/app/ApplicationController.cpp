#include "app/ApplicationController.h"
#include "app/AppActions.h"
#include "app/AppState.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>

namespace mydbg::app {

void initialize_application(const char *initial_executable,
                            const char *initial_script,
                            debugger::LldbEngine &engine,
                            debugger::scripting::PythonRuntime &python,
                            UiState &ui) {
  if (!ui.theme_dark) {
    ui.theme_sync_pending = true;
    engine.execute_command("theme light");
  }
  if (initial_executable != nullptr) {
    std::strncpy(ui.executable_path.data(), initial_executable,
                 ui.executable_path.size() - 1);
    engine.launch(initial_executable);
  }
  if (initial_script != nullptr) {
    std::strncpy(ui.script_path.data(), initial_script,
                 ui.script_path.size() - 1);
    ui.python_console_message = python.run_file(initial_script)
                                    ? l10n::text(l10n::Key::AppScriptQueued)
                                    : l10n::text(l10n::Key::AppScriptRejected);
  }
}

void update_application_session(debugger::SessionSnapshot &snapshot,
                                debugger::SessionStore &sessions, UiState &ui) {
  ui.session_status = snapshot.session.sha256.empty()
                          ? debugger::SessionStatus{}
                          : sessions.status(snapshot.session.sha256);
  if (ui.session_status.identity == snapshot.session) {
    snapshot.session_analysis_revision = ui.session_status.analysis_revision;
  }
  if (ui.session_clear.valid() &&
      ui.session_clear.wait_for(std::chrono::milliseconds{0})) {
    const auto result = ui.session_clear.get();
    ui.session_action_message = result.message;
    ui.session_clear = {};
  }
  if (ui.observed_session != snapshot.session ||
      ui.cursor_generation != snapshot.generation) {
    if (ui.observed_session.sha256 != snapshot.session.sha256)
      ui.session_action_message.clear();
    ui.observed_session = snapshot.session;
    reset_navigation_history(ui);
    ui.memory_type_hints.clear();
    ui.memory_hints_serial = 0;
    ui.decompiler_selection_anchor.reset();
    ui.decompiler_selection_start.reset();
    ui.decompiler_selection_end.reset();
    ui.decompiler_target.reset();
    ui.decompiler_context_target.reset();
    ui.decompiler_context_load_address.reset();
    ui.decompiler_dialog = DecompilerDialog::None;
    ui.decompiler_message.clear();
    ui.comment_address.reset();
    ui.comment_editor_requested = false;
    ui.comment_error.clear();
    ui.disassembly_text_cache.reset();
    ui.disassembly_graph_state.reset();
    close_condition_editor(ui);
  }
}

bool synchronize_application_theme(const debugger::SessionSnapshot &snapshot,
                                   UiState &ui) {
  if (ui.theme_sync_pending && snapshot.theme_dark == ui.theme_dark) {
    ui.theme_sync_pending = false;
  } else if (!ui.theme_sync_pending && snapshot.theme_dark != ui.theme_dark) {
    ui.theme_dark = snapshot.theme_dark;
    return true;
  }
  return false;
}

void update_application_selection(const debugger::SessionSnapshot &snapshot,
                                  UiState &ui) {
  if (snapshot.state == debugger::SessionState::Stopped &&
      (ui.cursor_generation != snapshot.generation ||
       ui.cursor_stop_revision != snapshot.stop_revision)) {
    if (ui.cursor_generation != snapshot.generation) {
      reset_navigation_history(ui);
    }
    ui.decompiler_keyboard_line.reset();
    ui.decompiler_keyboard_span.reset();
    ui.navigation_source_restore.reset();
    ui.disassembly_cursor = snapshot.pc;
    ui.disassembly_scroll_target.reset();
    ui.cursor_generation = snapshot.generation;
    ui.cursor_stop_revision = snapshot.stop_revision;
    ui.decompiler_scroll_selection = std::numeric_limits<std::uint64_t>::max();
  }
}

std::shared_ptr<const debugger::DecompilerSnapshot>
update_application_decompiler(const debugger::SessionSnapshot &snapshot,
                              debugger::DecompilerEngine &decompiler,
                              UiState &ui) {
  if (snapshot.state == debugger::SessionState::Stopped) {
    if (const auto file_address = selected_file_address(snapshot, ui)) {
      const auto *module = module_for_address(snapshot, ui.disassembly_cursor);
      const std::string &module_path =
          module != nullptr ? module->path : snapshot.pc_module_path;
      request_decompilation(decompiler, snapshot, module_path, *file_address,
                            ui.disassembly_cursor);
    }
  } else {
    const auto active_decompilation = decompiler.snapshot();
    if (active_decompilation->loading ||
        !active_decompilation->executable_path.empty()) {
      decompiler.cancel(snapshot.generation);
    }
  }
  const auto decompiled = decompiler.snapshot();
  if (!decompiled->loading && decompiled->error.empty() &&
      decompiled->generation == snapshot.generation &&
      decompiled->session == snapshot.session &&
      ui.memory_hints_serial != decompiled->request_serial) {
    ui.memory_hints_serial = decompiled->request_serial;
    std::erase_if(ui.memory_type_hints, [&](const MemoryTypeHint &hint) {
      return hint.module_path == decompiled->executable_path;
    });
    for (const auto &hint : decompiled->memory_hints) {
      if (const auto address = load_address_for_file(
              snapshot, decompiled->executable_path, hint.file_address)) {
        ui.memory_type_hints.push_back(
            {.address = *address,
             .label = hint.label,
             .type = hint.type,
             .string = hint.is_string,
             .module_path = decompiled->executable_path});
      }
    }
  }
  return decompiled;
}

} // namespace mydbg::app
