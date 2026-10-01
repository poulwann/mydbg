#include "app/ApplicationController.h"
#include "app/AppActions.h"
#include "app/AppState.h"
#include "backend/lldb/LldbEngine.h"

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
  if (!ui.workspace.theme_dark) {
    ui.workspace.theme_sync_pending = true;
    engine.execute_command("theme light");
  }
  if (initial_executable != nullptr) {
    std::strncpy(ui.session.executable_path.data(), initial_executable,
                 ui.session.executable_path.size() - 1);
    engine.launch(initial_executable);
  }
  if (initial_script != nullptr) {
    std::strncpy(ui.python.path.data(), initial_script,
                 ui.python.path.size() - 1);
    ui.python.console_message = python.run_file(initial_script)
                                    ? l10n::text(l10n::Key::AppScriptQueued)
                                    : l10n::text(l10n::Key::AppScriptRejected);
  }
}

void update_application_session(debugger::SessionSnapshot &snapshot,
                                debugger::SessionStore &sessions, UiState &ui) {
  ui.session.status = snapshot.session.sha256.empty()
                          ? debugger::SessionStatus{}
                          : sessions.status(snapshot.session.sha256);
  if (ui.session.status.identity == snapshot.session) {
    snapshot.session_analysis_revision = ui.session.status.analysis_revision;
  }
  if (ui.session.clear.valid() &&
      ui.session.clear.wait_for(std::chrono::milliseconds{0})) {
    const auto result = ui.session.clear.get();
    ui.session.action_message = result.message;
    ui.session.clear = {};
  }
  if (ui.session.observed != snapshot.session ||
      ui.navigation.cursor_generation != snapshot.generation) {
    if (ui.session.observed.sha256 != snapshot.session.sha256)
      ui.session.action_message.clear();
    ui.session.observed = snapshot.session;
    reset_navigation_history(ui);
    ui.memory.type_hints.clear();
    ui.memory.hints_serial = 0;
    ui.decompiler.selection_anchor.reset();
    ui.decompiler.selection_start.reset();
    ui.decompiler.selection_end.reset();
    ui.decompiler.target.reset();
    ui.decompiler.context_target.reset();
    ui.decompiler.context_load_address.reset();
    ui.decompiler.dialog = DecompilerDialog::None;
    ui.decompiler.message.clear();
    ui.comments.address.reset();
    ui.comments.editor_requested = false;
    ui.comments.error.clear();
    ui.navigation.disassembly_text_cache.reset();
    ui.navigation.disassembly_graph_state.reset();
    close_condition_editor(ui);
  }
}

bool synchronize_application_theme(const debugger::SessionSnapshot &snapshot,
                                   UiState &ui) {
  if (ui.workspace.theme_sync_pending &&
      snapshot.theme_dark == ui.workspace.theme_dark) {
    ui.workspace.theme_sync_pending = false;
  } else if (!ui.workspace.theme_sync_pending &&
             snapshot.theme_dark != ui.workspace.theme_dark) {
    ui.workspace.theme_dark = snapshot.theme_dark;
    return true;
  }
  return false;
}

void update_application_selection(const debugger::SessionSnapshot &snapshot,
                                  UiState &ui) {
  if (snapshot.state == debugger::SessionState::Stopped &&
      (ui.navigation.cursor_generation != snapshot.generation ||
       ui.navigation.cursor_stop_revision != snapshot.stop_revision)) {
    if (ui.navigation.cursor_generation != snapshot.generation) {
      reset_navigation_history(ui);
    }
    ui.decompiler.keyboard_line.reset();
    ui.decompiler.keyboard_span.reset();
    ui.navigation.source_restore.reset();
    ui.navigation.disassembly_cursor = snapshot.pc;
    ui.navigation.disassembly_scroll_target.reset();
    ui.navigation.cursor_generation = snapshot.generation;
    ui.navigation.cursor_stop_revision = snapshot.stop_revision;
    ui.decompiler.scroll_selection = std::numeric_limits<std::uint64_t>::max();
  }
}

std::shared_ptr<const debugger::DecompilerSnapshot>
update_application_decompiler(const debugger::SessionSnapshot &snapshot,
                              debugger::DecompilerEngine &decompiler,
                              UiState &ui) {
  if (snapshot.state == debugger::SessionState::Stopped) {
    if (const auto file_address = selected_file_address(snapshot, ui)) {
      const auto *module =
          module_for_address(snapshot, ui.navigation.disassembly_cursor);
      const std::string &module_path =
          module != nullptr ? module->path : snapshot.pc_module_path;
      request_decompilation(decompiler, snapshot, module_path, *file_address,
                            ui.navigation.disassembly_cursor);
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
      ui.memory.hints_serial != decompiled->request_serial) {
    ui.memory.hints_serial = decompiled->request_serial;
    std::erase_if(ui.memory.type_hints, [&](const MemoryTypeHint &hint) {
      return hint.module_path == decompiled->executable_path;
    });
    for (const auto &hint : decompiled->memory_hints) {
      if (const auto address = load_address_for_file(
              snapshot, decompiled->executable_path, hint.file_address)) {
        ui.memory.type_hints.push_back(
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
