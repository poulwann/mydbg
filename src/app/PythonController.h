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

struct PythonState;
struct FileDialogState;
enum class ScriptAction : std::size_t;

struct PythonFileDialogState {
  std::string error;
  bool open = false;
};

const char *script_status_text(debugger::scripting::ScriptStatus status);
void execute_console_input(std::string command, debugger::LldbEngine &engine,
                           debugger::scripting::PythonRuntime &runtime,
                           PythonState &state, bool control_lease);
void load_script_source(PythonState &state, const std::string &file);
void save_script_source(PythonState &state);
// True only when a new debug session starts; the caller arranges its workspace
// immediately, after the controller has updated the console message.
bool start_python_debugger(debugger::scripting::PythonRuntime &runtime,
                           PythonState &state);
void run_python_script(debugger::scripting::PythonRuntime &runtime,
                       PythonState &state);
void toggle_script_breakpoint(debugger::scripting::PythonRuntime &runtime,
                              PythonState &state);
bool script_action_enabled(ScriptAction action,
                           const debugger::scripting::ScriptSnapshot &script,
                           const PythonState &state);
bool execute_script_action(ScriptAction action,
                           const debugger::scripting::ScriptSnapshot &script,
                           debugger::scripting::PythonRuntime &runtime,
                           PythonState &state);
PythonFileDialogState python_sync_script_file(PythonState &state,
                                              FileDialogState &files);
void python_sync_editor_execution(
    const debugger::scripting::ScriptSnapshot &script, PythonState &state);
void python_load_ctf_demo(debugger::scripting::PythonRuntime &runtime,
                          PythonState &state);

} // namespace mydbg::app
