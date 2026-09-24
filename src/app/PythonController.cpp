#include "app/PythonController.h"
#include "app/AppState.h"
#include "localization/Localization.h"
#include "scripting/PythonRuntime.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <utility>

namespace mydbg::app {

const char *script_status_text(debugger::scripting::ScriptStatus status) {
  using debugger::scripting::ScriptStatus;
  switch (status) {
  case ScriptStatus::Idle:
    return l10n::text(l10n::Key::GuiPythonStatusIdle);
  case ScriptStatus::Queued:
    return l10n::text(l10n::Key::GuiPythonStatusQueued);
  case ScriptStatus::Running:
    return l10n::text(l10n::Key::GuiPythonStatusRunning);
  case ScriptStatus::Cancelling:
    return l10n::text(l10n::Key::GuiPythonStatusCancelling);
  case ScriptStatus::Succeeded:
    return l10n::text(l10n::Key::GuiPythonStatusSucceeded);
  case ScriptStatus::Failed:
    return l10n::text(l10n::Key::GuiPythonStatusFailed);
  case ScriptStatus::Cancelled:
    return l10n::text(l10n::Key::GuiPythonStatusCancelled);
  case ScriptStatus::ShuttingDown:
    return l10n::text(l10n::Key::GuiPythonStatusShuttingDown);
  }
  return l10n::text(l10n::Key::GuiPythonStatusUnknown);
}

void execute_console_input(std::string command, debugger::LldbEngine &engine,
                           debugger::scripting::PythonRuntime &runtime,
                           UiState &ui, bool control_lease) {
  const auto whitespace = [](unsigned char byte) { return std::isspace(byte); };
  command.erase(command.begin(),
                std::find_if_not(command.begin(), command.end(), whitespace));
  while (!command.empty() &&
         std::isspace(static_cast<unsigned char>(command.back())) != 0) {
    command.pop_back();
  }
  if (command == "py status") {
    const auto script = runtime.snapshot();
    ui.python_console_message =
        script.file.empty()
            ? l10n::format(l10n::Key::GuiPythonConsoleStatus,
                           script_status_text(script.status))
            : l10n::format(l10n::Key::GuiPythonConsoleFileStatus,
                           script_status_text(script.status),
                           script.file.c_str());
  } else if (command == "py stop") {
    runtime.stop();
    ui.python_console_message =
        l10n::text(l10n::Key::GuiPythonCancellationRequested);
  } else if (command.starts_with("py run ")) {
    std::string file = command.substr(7);
    file.erase(file.begin(),
               std::find_if_not(file.begin(), file.end(), whitespace));
    if (file.empty()) {
      ui.python_console_message = l10n::text(l10n::Key::GuiPythonRunUsage);
    } else {
      std::snprintf(ui.script_path.data(), ui.script_path.size(), "%s",
                    file.c_str());
      ui.python_console_message =
          runtime.run_file(file) ? l10n::text(l10n::Key::GuiPythonScriptQueued)
                                 : l10n::text(l10n::Key::GuiPythonRuntimeBusy);
    }
  } else if (command == "py" || command.starts_with("py ")) {
    ui.python_console_message = l10n::text(l10n::Key::GuiPythonCommandUsage);
  } else if (control_lease) {
    ui.python_console_message = l10n::text(l10n::Key::GuiPythonControlOwned);
  } else {
    engine.execute_command(std::move(command));
    ui.python_console_message.clear();
  }
}

void load_script_source(UiState &ui, const std::string &file) {
  constexpr std::uintmax_t maximum_editor_bytes = 4U * 1024U * 1024U;
  std::error_code size_error;
  const std::uintmax_t size = std::filesystem::file_size(file, size_error);
  if (size_error || size > maximum_editor_bytes) {
    ui.script_file_error =
        size_error ? l10n::format(l10n::Key::GuiPythonInspectScriptFailed,
                                  size_error.message().c_str())
                   : l10n::text(l10n::Key::GuiPythonEditorSizeLimit);
    return;
  }
  std::ifstream input{file, std::ios::binary};
  if (!input) {
    ui.script_file_error = l10n::text(l10n::Key::GuiPythonOpenScriptFailed);
    return;
  }
  std::string source(static_cast<std::size_t>(size), '\0');
  input.read(source.data(), static_cast<std::streamsize>(source.size()));
  if (!input && !input.eof()) {
    ui.script_file_error = l10n::text(l10n::Key::GuiPythonReadScriptFailed);
    return;
  }
  ui.script_editor.SetText(source);
  ui.script_loaded_path = file;
  ui.script_dirty = false;
  ui.script_file_error.clear();
}

void save_script_source(UiState &ui) {
  if (ui.script_path.front() == '\0') {
    ui.script_file_error = l10n::text(l10n::Key::GuiPythonSavePathRequired);
    return;
  }
  std::ofstream output{ui.script_path.data(),
                       std::ios::binary | std::ios::trunc};
  if (!output) {
    ui.script_file_error =
        l10n::text(l10n::Key::GuiPythonOpenScriptForWritingFailed);
    return;
  }
  const std::string source = ui.script_editor.GetText();
  output.write(source.data(), static_cast<std::streamsize>(source.size()));
  if (!output) {
    ui.script_file_error = l10n::text(l10n::Key::GuiPythonWriteScriptFailed);
    return;
  }
  ui.script_loaded_path = ui.script_path.data();
  ui.script_dirty = false;
  ui.script_file_error.clear();
}

std::vector<std::uint32_t>
script_breakpoint_lines(const TextEditor::Breakpoints &breakpoints) {
  std::vector<std::uint32_t> result;
  result.reserve(breakpoints.size());
  for (const int line : breakpoints) {
    if (line > 0) {
      result.push_back(static_cast<std::uint32_t>(line));
    }
  }
  std::ranges::sort(result);
  return result;
}

bool start_python_debugger(debugger::scripting::PythonRuntime &runtime,
                           UiState &ui) {
  if (!runtime.debug_source(ui.script_path.data(), ui.script_editor.GetText(),
                            script_breakpoint_lines(ui.script_breakpoints))) {
    ui.python_console_message = l10n::text(l10n::Key::GuiPythonRuntimeBusy);
    return false;
  }
  ui.python_console_message = l10n::text(l10n::Key::GuiPythonDebuggerStarted);
  return true;
}

void run_python_script(debugger::scripting::PythonRuntime &runtime,
                       UiState &ui) {
  const bool started = runtime.debug_source(
      ui.script_path.data(), ui.script_editor.GetText(), {}, false);
  ui.python_console_message =
      started ? l10n::text(l10n::Key::GuiPythonScriptRunning)
              : l10n::text(l10n::Key::GuiPythonRuntimeBusy);
}

void toggle_script_breakpoint(debugger::scripting::PythonRuntime &runtime,
                              UiState &ui) {
  const int cursor_line = ui.script_editor.GetCursorPosition().mLine + 1;
  if (ui.script_breakpoints.contains(cursor_line)) {
    ui.script_breakpoints.erase(cursor_line);
  } else {
    ui.script_breakpoints.insert(cursor_line);
  }
  runtime.set_breakpoints(script_breakpoint_lines(ui.script_breakpoints));
}

bool script_action_enabled(ScriptAction action,
                           const debugger::scripting::ScriptSnapshot &script,
                           const UiState &ui) {
  const bool paused =
      script.debug_state == debugger::scripting::ScriptDebugState::Paused;
  switch (action) {
  case ScriptAction::DebugContinue:
    return paused || (!script.control_lease && !ui.script_loaded_path.empty());
  case ScriptAction::Run:
    return !script.control_lease && !ui.script_loaded_path.empty();
  case ScriptAction::ToggleBreakpoint:
    return !ui.script_loaded_path.empty();
  case ScriptAction::StepInto:
  case ScriptAction::StepOver:
  case ScriptAction::StepOut:
    return paused;
  case ScriptAction::Pause:
    return script.debug_state == debugger::scripting::ScriptDebugState::Running;
  case ScriptAction::Stop:
    return script.control_lease;
  case ScriptAction::Count:
    return false;
  }
  return false;
}

bool execute_script_action(ScriptAction action,
                           const debugger::scripting::ScriptSnapshot &script,
                           debugger::scripting::PythonRuntime &runtime,
                           UiState &ui) {
  switch (action) {
  case ScriptAction::DebugContinue:
    if (script.debug_state == debugger::scripting::ScriptDebugState::Paused) {
      runtime.continue_script();
    } else {
      return start_python_debugger(runtime, ui);
    }
    break;
  case ScriptAction::Run:
    run_python_script(runtime, ui);
    break;
  case ScriptAction::ToggleBreakpoint:
    toggle_script_breakpoint(runtime, ui);
    break;
  case ScriptAction::StepInto:
    runtime.step_into_script();
    break;
  case ScriptAction::StepOver:
    runtime.step_over_script();
    break;
  case ScriptAction::StepOut:
    runtime.step_out_script();
    break;
  case ScriptAction::Pause:
    runtime.pause_script();
    break;
  case ScriptAction::Stop:
    runtime.stop();
    break;
  case ScriptAction::Count:
    break;
  }
  return false;
}

PythonFileDialogState python_sync_script_file(UiState &ui) {
  std::optional<std::string> selected_script;
  std::string file_dialog_error;
  bool file_dialog_open = false;
  {
    const std::lock_guard lock{ui.file_dialog_mutex};
    selected_script = std::move(ui.selected_script);
    ui.selected_script.reset();
    if (ui.script_dialog) {
      file_dialog_error = ui.file_dialog_error;
      file_dialog_open = ui.file_dialog_open;
    }
  }
  if (selected_script) {
    std::snprintf(ui.script_path.data(), ui.script_path.size(), "%s",
                  selected_script->c_str());
    load_script_source(ui, *selected_script);
  } else if (ui.script_loaded_path.empty() && ui.script_path.front() != '\0') {
    load_script_source(ui, ui.script_path.data());
  }
  return {std::move(file_dialog_error), file_dialog_open};
}

void python_sync_editor_execution(
    const debugger::scripting::ScriptSnapshot &script, UiState &ui) {
  TextEditor::ErrorMarkers current_line;
  if (script.debug_state != debugger::scripting::ScriptDebugState::Inactive &&
      script.current_line > 0) {
    if (ui.script_execution_line != script.current_line) {
      ui.script_editor.SetCursorPosition(TextEditor::Coordinates{
          static_cast<int>(script.current_line - 1), 0});
      ui.script_execution_line = script.current_line;
    }
    current_line[static_cast<int>(script.current_line)] =
        script.debug_state == debugger::scripting::ScriptDebugState::Paused
            ? l10n::text(l10n::Key::GuiPythonExecutionPausedHere)
            : l10n::text(l10n::Key::GuiPythonExecutingLine);
    ui.script_editor.SetErrorMarkers(current_line);
  } else {
    ui.script_editor.SetErrorMarkers({});
    ui.script_execution_line = 0;
  }
  ui.script_editor.SetBreakpoints(ui.script_breakpoints);
  ui.script_editor.SetReadOnly(script.control_lease);
}

void python_load_ctf_demo(debugger::scripting::PythonRuntime &runtime,
                          UiState &ui) {
  std::snprintf(ui.script_path.data(), ui.script_path.size(), "%s",
                MYDBG_CTF_DEMO_SCRIPT);
  load_script_source(ui, ui.script_path.data());
  ui.script_breakpoints = {45, 51, 57, 61, 67, 73, 79, 88};
  runtime.set_breakpoints(script_breakpoint_lines(ui.script_breakpoints));
  ui.python_console_message = l10n::text(l10n::Key::GuiPythonCtfDemoLoaded);
}

} // namespace mydbg::app
