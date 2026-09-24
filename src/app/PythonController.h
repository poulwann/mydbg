#pragma once

#include <cstddef>
#include <string>

namespace debugger {
class LldbEngine;
namespace scripting {
class PythonRuntime;
struct ScriptSnapshot;
enum class ScriptStatus;
} // namespace scripting
} // namespace debugger

namespace mydbg::app {

struct UiState;
enum class ScriptAction : std::size_t;

struct PythonFileDialogState {
  std::string error;
  bool open = false;
};

const char *script_status_text(debugger::scripting::ScriptStatus status);
void execute_console_input(std::string command, debugger::LldbEngine &engine,
                           debugger::scripting::PythonRuntime &runtime,
                           UiState &ui, bool control_lease);
void load_script_source(UiState &ui, const std::string &file);
void save_script_source(UiState &ui);
// True only when a new debug session starts; the caller arranges its workspace
// immediately, after the controller has updated the console message.
bool start_python_debugger(debugger::scripting::PythonRuntime &runtime,
                           UiState &ui);
void run_python_script(debugger::scripting::PythonRuntime &runtime,
                       UiState &ui);
void toggle_script_breakpoint(debugger::scripting::PythonRuntime &runtime,
                              UiState &ui);
bool script_action_enabled(ScriptAction action,
                           const debugger::scripting::ScriptSnapshot &script,
                           const UiState &ui);
bool execute_script_action(ScriptAction action,
                           const debugger::scripting::ScriptSnapshot &script,
                           debugger::scripting::PythonRuntime &runtime,
                           UiState &ui);
PythonFileDialogState python_sync_script_file(UiState &ui);
void python_sync_editor_execution(
    const debugger::scripting::ScriptSnapshot &script, UiState &ui);
void python_load_ctf_demo(debugger::scripting::PythonRuntime &runtime,
                          UiState &ui);

} // namespace mydbg::app
