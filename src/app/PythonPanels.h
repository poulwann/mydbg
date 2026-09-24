#pragma once

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
namespace scripting {
class PythonRuntime;
struct ScriptSnapshot;
} // namespace scripting
} // namespace debugger

namespace mydbg::app {

struct UiState;

void dispatch_contextual_shortcuts(
    const debugger::SessionSnapshot &snapshot, debugger::LldbEngine &engine,
    debugger::scripting::PythonRuntime &runtime, UiState &ui,
    const debugger::scripting::ScriptSnapshot &script);
void draw_python_panel(debugger::scripting::PythonRuntime &runtime,
                       UiState &ui);
void draw_console_panel(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine,
                        debugger::scripting::PythonRuntime &runtime,
                        UiState &ui, bool control_lease);

} // namespace mydbg::app
