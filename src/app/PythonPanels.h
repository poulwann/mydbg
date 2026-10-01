#pragma once

struct SDL_Window;

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
namespace scripting {
class PythonRuntime;
struct ScriptSnapshot;
} // namespace scripting
} // namespace debugger

namespace mydbg::app {

struct PythonState;
struct FileDialogState;
struct WorkspaceState;
void arrange_python_debug_workspace();

void draw_python_panel(debugger::scripting::PythonRuntime &runtime,
                       PythonState &state, FileDialogState &files,
                       const WorkspaceState &workspace, SDL_Window *window);
void draw_console_panel(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine,
                        debugger::scripting::PythonRuntime &runtime,
                        PythonState &state, bool control_lease);

} // namespace mydbg::app
